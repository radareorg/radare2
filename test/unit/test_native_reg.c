#include <r_core.h>
#include "../../libr/debug/p/native/reg_vector.h"
#include "minunit.h"

static bool test_x86_layout(void) {
	ut8 state[4096], original[4096], arena[2272];
	NativeX86Layout layout = { 8, 600, 900, 1000, 1600 };
	int i, bits, width;
	for (bits = 32; bits <= 64; bits += 32) {
		for (width = 128; width <= 512; width *= 2) {
			for (i = 0; i < sizeof (state); i++) {
				state[i] = i ^ (i >> 8);
			}
			memcpy (original, state, sizeof (state));
			memset (arena, 0, sizeof (arena));
			mu_assert_true (native_x86_transfer (arena, sizeof (arena), state, sizeof (state), &layout, bits, width, false), "read native layout");
			mu_assert_memeq (arena + 160, state + 168, 16, "XMM low bytes");
			if (width >= 256) {
				mu_assert_memeq (arena + 176, state + 600, 16, "YMM high bytes");
			}
			if (width == 512) {
				mu_assert_memeq (arena + 192, state + 1000, 32, "ZMM high bytes");
				if (bits == 64) {
					mu_assert_memeq (arena + 160 + 31 * 64, state + 1600 + 15 * 64, 64, "ZMM31");
				}
			}
			arena[160] ^= 0xff;
			mu_assert_true (native_x86_transfer (arena, sizeof (arena), state, sizeof (state), &layout, bits, width, true), "write native layout");
			original[168] ^= 0xff;
			mu_assert_memeq (state, original, sizeof (state), "preserve all other native state");
			mu_assert_true (!native_x86_transfer (arena, 160, state, sizeof (state), &layout, bits, width, true), "reject short arena");
			mu_assert_memeq (state, original, sizeof (state), "failed write is atomic");
			RReg *reg = r_reg_new ();
			char *profile = native_x86_profile (strdup (""), bits, width);
			mu_assert_true (r_reg_set_profile_string (reg, profile), "parse shared profile");
			mu_assert_eq (native_vector_width (reg, width == 512? "zmm0": width == 256? "ymm0": "xmm0"), width, "profile width");
			mu_assert_true (r_reg_set_bytes (reg, R_REG_TYPE_FPU, arena, sizeof (arena)), "load arena");
			RRegItem *xmm = r_reg_get (reg, "xmm0l", -1);
			mu_assert_eq (r_reg_get_value (reg, xmm), r_read_le64 (arena + 160), "low alias");
			r_unref (xmm);
			free (profile);
			r_reg_free (reg);
		}
	}
	mu_end;
}

static bool test_arm64_layout(void) {
	ut8 state[9000], original[9000], arena[9000];
	int be, vl, i;
	for (be = 0; be <= 1; be++) {
		for (vl = 16; vl <= 256; vl += 16) {
			for (i = 0; i < sizeof (state); i++) {
				state[i] = i ^ (i >> 8);
			}
			memcpy (original, state, sizeof (state));
			mu_assert_true (native_arm64_fpsimd (arena, sizeof (arena), state, 528, vl, true, be, false), "read FPSIMD");
			mu_assert_eq (arena[0], state[be? 8: 0], "FPSIMD low chunk");
			mu_assert_eq (arena[8], state[be? 0: 8], "FPSIMD high chunk");
			if (vl > 16) {
				mu_assert_eq (arena[16], 0, "FPSIMD clears upper Z bytes");
			}
			mu_assert_eq (arena[32 * vl], 0, "FPSIMD clears predicates");
			mu_assert_true (native_arm64_fpsimd (arena, sizeof (arena), state, 528, vl, true, be, true), "write FPSIMD");
			mu_assert_memeq (state, original, sizeof (state), "FPSIMD round trip preserves padding");
			mu_assert_true (native_arm64_sve (arena, sizeof (arena), state, sizeof (state), vl, be, false), "read SVE");
			mu_assert_eq (arena[0], state[16 + (be? 7: 0)], "SVE chunk endian");
			mu_assert_eq (arena[32 * vl], state[16 + 32 * vl + (be? R_MIN (vl / 8, 8) - 1: 0)], "predicate endian");
			mu_assert_true (native_arm64_sve (arena, sizeof (arena), state, sizeof (state), vl, be, true), "write SVE");
			mu_assert_memeq (state, original, sizeof (state), "SVE round trip preserves header and padding");
			mu_assert_true (!native_arm64_sve (arena, 4, state, sizeof (state), vl, be, true), "reject short arena");
			mu_assert_memeq (state, original, sizeof (state), "failed SVE write is atomic");
			RReg *reg = r_reg_new ();
			r_reg_set_endian (reg, be? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE);
			char *profile = native_arm64_profile (strdup (""), vl, true);
			mu_assert_true (r_reg_set_profile_string (reg, profile), "SVE profile");
			mu_assert_eq (native_vector_width (reg, "z31"), vl * 8, "SVE width");
			mu_assert_eq (native_vector_width (reg, "p15"), vl, "predicate width");
			mu_assert_eq (native_vector_width (reg, "ffr"), vl, "FFR width");
			mu_assert_true (r_reg_set_bytes (reg, R_REG_TYPE_FPU, arena, sizeof (arena)), "load SVE arena");
			RRegItem *byte = r_reg_get (reg, "b0", -1);
			mu_assert_eq (r_reg_get_value (reg, byte), original[16], "SVE scalar alias endian");
			r_unref (byte);
			free (profile);
			r_reg_free (reg);
		}
	}
	mu_end;
}

#if __linux__ && __x86_64__
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>

typedef struct {
	RIO io;
	ut8 *state;
	int size;
	bool xstate;
} NativeMock;

static long mock_ptrace(RIO *io, r_ptrace_request_t request, pid_t pid, void *addr, r_ptrace_data_t data) {
	NativeMock *mock = (NativeMock *)io;
	if (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) {
		struct iovec *iov = (struct iovec *)data;
		if (!mock->xstate || (size_t)addr != NT_X86_XSTATE || iov->iov_len < mock->size) {
			errno = ENODEV;
			return -1;
		}
		if (request == PTRACE_GETREGSET) {
			memcpy (iov->iov_base, mock->state, mock->size);
			iov->iov_len = mock->size;
		} else {
			memcpy (mock->state, iov->iov_base, mock->size);
		}
		return 0;
	}
	if (request == PTRACE_GETFPREGS) {
		memcpy ((void *)data, mock->state, 512);
		return 0;
	}
	if (request == PTRACE_SETFPREGS) {
		memcpy (mock->state, (void *)data, 512);
		return 0;
	}
	return -1;
}

static bool test_linux_xstate(void) {
	ut32 a, b, c, d;
	native_x86_cpuid (0, 0, &a, &b, &c, &d);
	if (a >= 0xd) {
		native_x86_cpuid (0xd, 0, &a, &b, &c, &d);
	} else {
		a = 0;
		c = 512;
	}
	NativeMock mock = { .size = R_MAX (c, 512) };
	mock.state = malloc (mock.size);
	ut8 *expected = malloc (mock.size);
	mu_assert_notnull (mock.state, "allocate XSAVE state");
	mu_assert_notnull (expected, "allocate expected state");
	RDebug *dbg = r_debug_new (true);
	mu_assert_true (r_debug_use (dbg, "native"), "native plugin");
	dbg->iob.io = &mock.io;
	dbg->iob.ptrace = mock_ptrace;
	dbg->pid = dbg->tid = 1;
	RDebugPlugin *plugin = dbg->current->plugin;
	int mode, i;
	for (mode = 0; mode < 2; mode++) {
		mock.xstate = mode && c >= 576;
		for (i = 0; i < mock.size; i++) {
			mock.state[i] = i ^ (i >> 8);
		}
		if (mock.xstate) {
			r_write_le64 (mock.state + 464, a & 0xe7);
			memset (mock.state + 512, 0, 64);
		}
		memcpy (expected, mock.state, mock.size);
		char *profile = plugin->reg_profile (dbg);
		mu_assert_true (r_reg_set_profile_string (dbg->reg, profile), "native XSAVE profile");
		free (profile);
		ut8 arena[2272];
		mu_assert_true (plugin->reg_read (dbg, R_REG_TYPE_FPU, arena, sizeof (arena)), "native XSAVE read or fallback");
		arena[160] ^= 0xff;
		expected[160] ^= 0xff;
		if (mock.xstate) {
			int width = native_vector_width (dbg->reg, "zmm0")? 512: native_vector_width (dbg->reg, "ymm0")? 256: 128;
			r_write_le64 (expected + 512, width == 512? 0xe7: width == 256? 7: 3);
		}
		mu_assert_true (plugin->reg_write (dbg, R_REG_TYPE_FPU, arena, sizeof (arena)), "native XSAVE write or fallback");
		mu_assert_memeq (mock.state, expected, mock.size, "preserve unrelated XSAVE fields and enable written components");
	}
	dbg->pid = dbg->tid = -1;
	r_debug_free (dbg);
	free (expected);
	free (mock.state);
	mu_end;
}
#endif

#if (__APPLE__ || __linux__) && (__aarch64__ || __arm64__ || __x86_64__)
#if __APPLE__
#include <mach/mach.h>
#include <pthread.h>
static void *native_wait(void *arg) {
	char byte;
	read (*(int *)arg, &byte, 1);
	return NULL;
}
#else
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
static long native_test_ptrace(RIO *io, r_ptrace_request_t request, pid_t pid, void *addr, r_ptrace_data_t data) {
	long ret = ptrace (request, pid, addr, data);
	if (ret == -1) {
		fprintf (stderr, "ptrace request %d: %s\n", (int)request, strerror (errno));
	}
	return ret;
}
#endif

static bool test_native_live(void) {
	RCore *core = r_core_new ();
	RDebug *dbg = core->dbg;
	core->io->want_ptrace_wrap = false;
	mu_assert_true (r_debug_use (dbg, "native"), "select native debugger");
#if __APPLE__
	int fds[2];
	pthread_t worker;
	mu_assert_eq (pipe (fds), 0, "create worker pipe");
	mu_assert_eq (pthread_create (&worker, NULL, native_wait, &fds[0]), 0, "create worker");
	thread_t thread = pthread_mach_thread_np (worker);
	mu_assert_eq (thread_suspend (thread), KERN_SUCCESS, "suspend worker");
	dbg->pid = getpid ();
	dbg->tid = thread;
#else
	dbg->iob.ptrace = native_test_ptrace;
	pid_t child = fork ();
	mu_assert_true (child >= 0, "fork tracee");
	if (!child) {
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL)) {
			_exit (77);
		}
		raise (SIGSTOP);
		_exit (0);
	}
	int status;
	waitpid (child, &status, 0);
	mu_assert_true (WIFSTOPPED (status), "tracee stopped");
	dbg->pid = dbg->tid = child;
#endif
	RDebugPlugin *plugin = dbg->current->plugin;
	char *profile = plugin->reg_profile (dbg);
	bool ok = profile && r_reg_set_profile_string (dbg->reg, profile);
	free (profile);
	ok = ok && r_debug_reg_sync (dbg, R_REG_TYPE_FPU, false);
#if __x86_64__
	const char *name = native_vector_width (dbg->reg, "zmm0")? "zmm0": native_vector_width (dbg->reg, "ymm0")? "ymm0": "xmm0";
#else
	const char *name = native_vector_width (dbg->reg, "z0")? "z0": "v0";
#endif
	RRegItem *item = r_reg_get (dbg->reg, name, -1);
	ut8 original[256], value[256], actual[256];
	int size = item? item->size / 8: 0;
	int i;
	for (i = 0; i < sizeof (value); i++) {
		value[i] = 0xa5 ^ i;
	}
	ok = ok && size && size <= sizeof (value) && r_reg_get_value_bytes (dbg->reg, item, original, size);
	bool saved = ok;
	ok = ok && r_reg_set_value_bytes (dbg->reg, item, value, size)
		&& r_debug_reg_sync (dbg, R_REG_TYPE_FPU, true)
		&& r_debug_reg_sync (dbg, R_REG_TYPE_FPU, false)
		&& r_reg_get_value_bytes (dbg->reg, item, actual, size) && !memcmp (actual, value, size);
	if (saved) {
		ok = r_reg_set_value_bytes (dbg->reg, item, original, size)
			&& r_debug_reg_sync (dbg, R_REG_TYPE_FPU, true) && ok;
	}
	printf ("(%s, %d bits) ", name, size * 8);
	r_unref (item);
#if __APPLE__
	thread_resume (thread);
	write (fds[1], "x", 1);
	pthread_join (worker, NULL);
	close (fds[0]);
	close (fds[1]);
#else
	ptrace (PTRACE_KILL, child, NULL, NULL);
	waitpid (child, &status, 0);
#endif
	dbg->pid = dbg->tid = -1;
	r_core_free (core);
	mu_assert_true (ok, "native vector read/write/restore");
	mu_end;
}
#endif

int main(int argc, char **argv) {
	mu_run_test (test_x86_layout);
	mu_run_test (test_arm64_layout);
#if __linux__ && __x86_64__
	mu_run_test (test_linux_xstate);
#endif
#if (__APPLE__ || __linux__) && (__aarch64__ || __arm64__ || __x86_64__)
	if (argc > 1 && !strcmp (argv[1], "--live")) {
		mu_run_test (test_native_live);
	}
#endif
	return tests_passed != tests_run;
}
