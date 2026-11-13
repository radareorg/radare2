/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_userconf.h>

#if DEBUGGER
#include <r_debug.h>
#include <r_core.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_anal.h>
#include <sys/uio.h>
#include "linux_debug.h"
#include "../procfs.h"

#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>

#include "linux_ptrace.h"

#include "../reg_vector.h"

#if __x86_64__
static ut8 *linux_xstate(RDebug *dbg, struct iovec *iov, NativeX86Layout *layout, int *width) {
	ut32 a, b, c, d;
	native_x86_cpuid (0, 0, &a, &b, &c, &d);
	if (a < 0xd) {
		return NULL;
	}
	native_x86_cpuid (0xd, 0, &a, &b, &c, &d);
	if (c < 576 || c > INT_MAX) {
		return NULL;
	}
	iov->iov_base = calloc (1, c);
	iov->iov_len = c;
	if (!iov->iov_base) {
		return NULL;
	}
	const int tid = dbg->tid > 0? dbg->tid: dbg->pid;
	ut8 *state = iov->iov_base;
	if (tid <= 0 || r_debug_ptrace (dbg, PTRACE_GETREGSET, tid, (void *)NT_X86_XSTATE, iov)
			|| iov->iov_len < 576 || (r_read_le64 (state + 520) >> 63)) {
		free (state);
		return NULL;
	}
	// Linux exports the supported XCR0 mask in the legacy software-reserved area.
	const ut64 features = r_read_le64 (state + 464);
	int *offsets[] = { &layout->ymm, &layout->opmask, &layout->zmm, &layout->hi16 };
	const int ids[] = { 2, 5, 6, 7 };
	int i;
	for (i = 0; i < R_ARRAY_SIZE (ids); i++) {
		*offsets[i] = -1;
		if (features & (1ULL << ids[i])) {
			native_x86_cpuid (0xd, ids[i], &a, &b, &c, &d);
			if (b >= 576 && (ut64)b + a <= iov->iov_len) {
				*offsets[i] = b;
			}
		}
	}
	*width = layout->ymm < 0? 128: layout->opmask >= 0 && layout->zmm >= 0 && layout->hi16 >= 0? 512: 256;
	return state;
}

static int linux_vector_width(RDebug *dbg) {
	NativeX86Layout layout = {0};
	struct iovec iov;
	int width = 128;
	free (linux_xstate (dbg, &iov, &layout, &width));
	return width;
}

static bool linux_vector_regs(RDebug *dbg, ut8 *buf, int size, bool write) {
	NativeX86Layout layout = {0};
	struct iovec iov;
	int available = 128;
	ut8 *state = linux_xstate (dbg, &iov, &layout, &available);
	struct user_fpregs_struct legacy;
	const int tid = dbg->tid > 0? dbg->tid: dbg->pid;
	const int width = native_vector_width (dbg->reg, "zmm0")? 512: native_vector_width (dbg->reg, "ymm0")? 256: 128;
	bool ok = width <= available;
	if (ok && !state) {
		ok = !r_debug_ptrace (dbg, PTRACE_GETFPREGS, tid, NULL, &legacy);
	}
	if (ok) {
		ok = native_x86_transfer (buf, size, state? state: (ut8 *)&legacy,
			state? iov.iov_len: sizeof (legacy), &layout, dbg->bits, width, write);
	}
	if (ok && write) {
		if (state) {
			ut64 features = width == 512? 0xe7: width == 256? 7: 3;
			r_write_le64 (state + 512, r_read_le64 (state + 512) | features);
			ok = !r_debug_ptrace (dbg, PTRACE_SETREGSET, tid, (void *)NT_X86_XSTATE, &iov);
		} else {
			ok = !r_debug_ptrace (dbg, PTRACE_SETFPREGS, tid, NULL, &legacy);
		}
	}
	free (state);
	return ok;
}
#elif __aarch64__ || __arm64__
static int linux_sve_vl(RDebug *dbg) {
#ifdef NT_ARM_SVE
	struct user_sve_header header = {0};
	struct iovec iov = { &header, sizeof (header) };
	int tid = dbg->tid > 0? dbg->tid: dbg->pid;
	if (tid > 0 && !r_debug_ptrace (dbg, PTRACE_GETREGSET, tid, (void *)NT_ARM_SVE, &iov)
			&& iov.iov_len == sizeof (header) && header.vl >= 16 && header.vl <= 256 && !(header.vl & 15)) {
		return header.vl;
	}
#endif
	return 0;
}

static bool linux_vector_regs(RDebug *dbg, ut8 *buf, int size, bool write) {
	const int tid = dbg->tid > 0? dbg->tid: dbg->pid;
	const int vl = native_vector_width (dbg->reg, "z0") / 8;
#ifdef NT_ARM_SVE
	if (vl) {
		if (vl < 16 || vl > 256 || (vl & 15)) {
			return false;
		}
		const int vq = vl / 16;
		const int len = SVE_PT_SIZE (vq, SVE_PT_REGS_SVE);
		ut8 *state = calloc (1, len);
		if (!state) {
			return false;
		}
		struct iovec iov = { state, len };
		struct user_sve_header *header = (struct user_sve_header *)state;
		bool ok = !r_debug_ptrace (dbg, PTRACE_GETREGSET, tid, (void *)NT_ARM_SVE, &iov)
			&& iov.iov_len >= sizeof (*header) && header->vl == vl;
		if (ok && (header->flags & SVE_PT_REGS_MASK) == SVE_PT_REGS_FPSIMD) {
			ok = iov.iov_len >= SVE_PT_FPSIMD_OFFSET + 520;
			if (ok && !write) {
				ok = native_arm64_fpsimd (buf, size, state + SVE_PT_FPSIMD_OFFSET,
					iov.iov_len - SVE_PT_FPSIMD_OFFSET, vl, true, R_SYS_ENDIAN, false);
			}
		} else if (ok) {
			ok = iov.iov_len >= len;
			if (ok && !write) {
				ok = native_arm64_sve (buf, size, state, len, vl, R_SYS_ENDIAN, false);
			}
		}
		if (ok && write) {
			header->flags = (header->flags & ~SVE_PT_REGS_MASK) | SVE_PT_REGS_SVE;
			header->size = len;
			iov.iov_len = len;
			ok = native_arm64_sve (buf, size, state, len, vl, R_SYS_ENDIAN, true)
				&& !r_debug_ptrace (dbg, PTRACE_SETREGSET, tid, (void *)NT_ARM_SVE, &iov);
		}
		free (state);
		return ok;
	}
#endif
	ut8 state[528];
	struct iovec iov = { state, sizeof (state) };
	return !r_debug_ptrace (dbg, PTRACE_GETREGSET, tid, (void *)NT_PRFPREG, &iov)
		&& native_arm64_fpsimd (buf, size, state, iov.iov_len, 16, false, R_SYS_ENDIAN, write)
		&& (!write || !r_debug_ptrace (dbg, PTRACE_SETREGSET, tid, (void *)NT_PRFPREG, &iov));
}
#endif

static char *linux_reg_profile_base(RDebug *dbg) {
#if __arm__
#	include "reg/linux-arm.h"
#elif __riscv
#	include "reg/linux-riscv64.h"
#elif __arm64__ || __aarch64__
	const bool is64 = R_SYS_BITS_CHECK (dbg->bits, 64);
	if (is64) {
#		include "reg/linux-arm64.h"
	} else {
#		include "reg/linux-arm.h"
	}
#elif __mips__
	const bool is32 = R_SYS_BITS_CHECK (dbg->bits, 32);
	if (is32 && (dbg->bp->endian == 1)) {
#		include "reg/linux-mips.h"
	} else {
#		include "reg/linux-mips64.h"
	}
#elif __loongarch__
#		include "reg/linux-loongarch64.h"
#elif (__i386__ || __x86_64__)
	const bool is32 = R_SYS_BITS_CHECK (dbg->bits, 32);
	if (is32) {
#if __x86_64__
#		include "reg/linux-x64-32.h"
#else
#		include "reg/linux-x86.h"
#endif
	} else {
#		include "reg/linux-x64.h"
	}
#elif __powerpc__
	const bool is64 = R_SYS_BITS_CHECK (dbg->bits, 64);
	if (is64) {
#		include "reg/linux-ppc64.h"
	} else {
#		include "reg/linux-ppc.h"
	}
#elif __s390x__
	const bool is64 = R_SYS_BITS_CHECK (dbg->bits, 64);
	if (is64) {
#		include "reg/linux-zarch.h"
	} else {
#		include "reg/linux-s390x.h"
	}
#else
#	error "Unsupported Linux CPU"
	return NULL;
#endif
}

char *linux_reg_profile(RDebug *dbg) {
	char *base = linux_reg_profile_base (dbg);
#if __x86_64__
	return native_x86_profile (base, dbg->bits, linux_vector_width (dbg));
#elif __aarch64__ || __arm64__
	if (R_SYS_BITS_CHECK (dbg->bits, 64)) {
		const int vl = linux_sve_vl (dbg);
		return native_arm64_profile (base, vl? vl: 16, vl != 0);
	}
#endif
	return base;
}

static void linux_detach_all(RDebug *dbg);
static char *read_link(int pid, const char *file);
static bool linux_attach_single_pid(RDebug *dbg, int ptid);
static void linux_remove_thread(RDebug *dbg, int pid);
static void linux_add_new_thread(RDebug *dbg, int tid);
static bool linux_stop_thread(RDebug *dbg, int tid);
static bool linux_kill_thread(int tid, int signo);
static void linux_dbg_wait_break_main(RDebug *dbg);
static void linux_dbg_wait_break(RDebug *dbg);
static RDebugReasonType linux_handle_new_task(RDebug *dbg, int tid);

static bool is_syscall_stop(int status) {
	return WIFSTOPPED (status) && WSTOPSIG (status) == (SIGTRAP | 0x80);
}

static void syscall_state_key(char *buf, size_t buf_size, int pid, int tid, const char *name) {
	snprintf (buf, buf_size, "dbg.syscall.%d.%d.%s", pid, tid, name);
}

static bool syscall_resume(RDebug *dbg, int tid, bool trace_syscalls) {
	const int request = trace_syscalls? PTRACE_SYSCALL: PTRACE_CONT;
	if (r_debug_ptrace (dbg, request, tid, 0, 0) == -1) {
		r_sys_perror (trace_syscalls? "PTRACE_SYSCALL": "PTRACE_CONT");
		return false;
	}
	return true;
}

static bool syscall_fasttime_enabled(RDebug *dbg) {
	return dbg && dbg->options.fasttime;
}

static const char *syscall_hook_cmd(RDebug *dbg, const char *key) {
	if (!strcmp (key, "cmd.syscall.enter")) {
		return dbg? dbg->options.cmd_syscall_enter: NULL;
	}
	if (!strcmp (key, "cmd.syscall.leave")) {
		return dbg? dbg->options.cmd_syscall_leave: NULL;
	}
	return NULL;
}

static bool syscall_hooks_suppressed(RDebug *dbg) {
	return dbg && dbg->options.syscall_hook_suppress;
}

static bool syscall_hooks_enabled(RDebug *dbg) {
	return syscall_fasttime_enabled (dbg) || R_STR_ISNOTEMPTY (dbg->options.cmd_syscall_enter)
		|| R_STR_ISNOTEMPTY (dbg->options.cmd_syscall_leave);
}

static bool syscall_is_timer(RDebug *dbg, int syscall_num) {
	if (!dbg || !dbg->anal || !dbg->anal->syscall || syscall_num < 0) {
		return false;
	}
	const int nanosleep_num = r_syscall_get_num (dbg->anal->syscall, "nanosleep");
	const int clock_nanosleep_num = r_syscall_get_num (dbg->anal->syscall, "clock_nanosleep");
	return syscall_num == nanosleep_num || syscall_num == clock_nanosleep_num;
}

static bool syscall_run_cmd(RDebug *dbg, const char *key) {
	const char *cmd = syscall_hook_cmd (dbg, key);
	if (R_STR_ISEMPTY (cmd) || !dbg->coreb.cmd) {
		return true;
	}
	dbg->coreb.cmd (dbg->coreb.core, cmd);
	if (dbg->coreb.core) {
		RCore *core = (RCore *)dbg->coreb.core;
		r_cons_flush (core->cons);
	}
	return true;
}

static void syscall_fasttime_enter(RDebug *dbg, Sdb *sdb, int tid, int syscall_num) {
	if (!syscall_fasttime_enabled (dbg) || !syscall_is_timer (dbg, syscall_num)) {
		return;
	}
	const char *sn = dbg->reg? r_reg_alias_getname (dbg->reg, R_REG_ALIAS_SN): NULL;
	if (R_STR_ISNOTEMPTY (sn) && r_debug_reg_set (dbg, sn, UT64_MAX)) {
		char key[64];
		syscall_state_key (key, sizeof (key), dbg->pid, tid, "fasttime");
		sdb_bool_set (sdb, key, true, 0);
	}
}

static void syscall_fasttime_unset(RDebug *dbg, Sdb *sdb, int tid) {
	char key[64];
	syscall_state_key (key, sizeof (key), dbg->pid, tid, "fasttime");
	sdb_unset (sdb, key, 0);
}

static void syscall_fasttime_leave(RDebug *dbg, Sdb *sdb, int tid) {
	char key[64];
	syscall_state_key (key, sizeof (key), dbg->pid, tid, "fasttime");
	if (!sdb_bool_get (sdb, key, NULL)) {
		return;
	}
	const char *r0 = dbg->reg? r_reg_alias_getname (dbg->reg, R_REG_ALIAS_R0): NULL;
	if (R_STR_ISEMPTY (r0)) {
		r0 = dbg->reg? r_reg_alias_getname (dbg->reg, R_REG_ALIAS_A0): NULL;
	}
	if (R_STR_ISNOTEMPTY (r0)) {
		(void)r_debug_reg_set (dbg, r0, 0);
	}
	syscall_fasttime_unset (dbg, sdb, tid);
}

static bool syscall_handle_stop(RDebug *dbg, int tid) {
	if (syscall_hooks_suppressed (dbg)) {
		return false;
	}
	RCore *core = (RCore *)dbg->coreb.core;
	if (!core || !core->sdb) {
		return false;
	}
	char key[64];
	syscall_state_key (key, sizeof (key), dbg->pid, tid, "in");
	const bool in_syscall = sdb_bool_get (core->sdb, key, NULL);
	if (!in_syscall && !syscall_hooks_enabled (dbg)) {
		return false;
	}
	if (!r_debug_select (dbg, dbg->pid, tid)) {
		if (in_syscall) {
			sdb_bool_set (core->sdb, key, false, 0);
			syscall_fasttime_unset (dbg, core->sdb, tid);
		}
		return false;
	}
	if (!in_syscall) {
		sdb_bool_set (core->sdb, key, true, 0);
		syscall_run_cmd (dbg, "cmd.syscall.enter");
		if (syscall_fasttime_enabled (dbg)) {
			bool err = false;
			int syscall_num = (int)r_debug_reg_get_err (dbg, "SN", &err);
			if (!err) {
				syscall_fasttime_enter (dbg, core->sdb, tid, syscall_num);
			}
		}
	} else {
		sdb_bool_set (core->sdb, key, false, 0);
		syscall_fasttime_leave (dbg, core->sdb, tid);
		syscall_run_cmd (dbg, "cmd.syscall.leave");
	}
	return syscall_resume (dbg, tid, !in_syscall || syscall_hooks_enabled (dbg));
}

int linux_handle_signals(RDebug *dbg, int tid) {
	RCore *core = dbg->coreb.core;
	siginfo_t siginfo = {0};
	int ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, tid, 0, (r_ptrace_data_t)&siginfo);
	if (ret == -1) {
		/* ESRCH means the process already went away :-/ */
		if (errno == ESRCH) {
			dbg->reason.type = R_DEBUG_REASON_DEAD;
			return true;
		}
		r_sys_perror ("ptrace GETSIGINFO");
		return false;
	}

	if (siginfo.si_signo > 0) {
		//siginfo_t newsiginfo = {0};
		//ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason.type = R_DEBUG_REASON_SIGNAL;
		dbg->reason.signum = siginfo.si_signo;
		dbg->stopaddr = (ut64)(size_t)siginfo.si_addr;
		//dbg->errno = siginfo.si_errno;
		// siginfo.si_code -> HWBKPT, USER, KERNEL or WHAT
		// TODO: DO MORE RDEBUGREASON HERE
		switch (dbg->reason.signum) {
		case SIGINT:
			dbg->reason.type = R_DEBUG_REASON_USERSUSP;
			break;
		case SIGSEGV:
			dbg->reason.type = R_DEBUG_REASON_SEGFAULT;
			break;
		case SIGSTOP:
			dbg->reason.type = R_DEBUG_REASON_STOPPED;
			break;
		case SIGTERM:
			dbg->reason.type = R_DEBUG_REASON_TERMINATED;
			break;
		case SIGTRAP:
		{
			if (dbg->options.glob_libs || dbg->options.glob_unlibs) {
				ut64 pc_addr = r_debug_reg_get (dbg, "PC");
				RBreakpointItem *b = r_bp_get_at (dbg->bp, pc_addr - dbg->options.bpsize);
				if (b && b->internal) {
					char *p = strstr (b->data, "dbg.");
					if (p) {
						if (r_str_startswith (p, "dbg.libs")) {
							const char *name = strstr (b->data, "sym.imp.dlopen")
								? r_reg_alias_getname (dbg->reg, R_REG_ALIAS_A0)
								: r_reg_alias_getname (dbg->reg, R_REG_ALIAS_A1);
							b->data = r_str_appendf (b->data, ";ps@r:%s", name);
							dbg->reason.type = R_DEBUG_REASON_NEW_LIB;
							break;
						} else if (r_str_startswith (p, "dbg.unlibs")) {
							dbg->reason.type = R_DEBUG_REASON_EXIT_LIB;
							break;
						}
					}
				}
			}
			if (dbg->reason.type != R_DEBUG_REASON_NEW_LIB &&
				dbg->reason.type != R_DEBUG_REASON_EXIT_LIB) {
				if (siginfo.si_code == TRAP_TRACE) {
					dbg->reason.type = R_DEBUG_REASON_STEP;
				} else {
					dbg->reason.bp_addr = (ut64)(size_t)siginfo.si_addr;
					dbg->reason.type = R_DEBUG_REASON_BREAKPOINT;
					// Switch to the thread that hit the breakpoint
					r_debug_select (dbg, dbg->pid, tid);
					dbg->tid = tid;
				}
			}
		} break;
		default:
			break;
		}
		if (dbg->reason.signum != SIGTRAP && (dbg->reason.signum != SIGINT || !r_cons_is_breaked (core->cons))) {
			const char *name = r_signal_tostring (dbg->reason.signum);
			eprintf ("[+] SIGNAL %d (aka %s) errno=%d addr=0x%08"PFMT64x " code=%d si_pid=%d ret=%d\n",
				siginfo.si_signo, name, siginfo.si_errno,
				(ut64) (size_t)siginfo.si_addr, siginfo.si_code, siginfo.si_pid, ret);
		}
		return true;
	}
	return false;
}

#if __ANDROID__
#undef PT_GETEVENTMSG
#define PT_GETEVENTMSG
#endif

// Used to remove breakpoints before detaching from a fork, without it the child
// will die upon hitting a breakpoint while not being traced
static void linux_remove_fork_bps(RDebug *dbg) {
	int prev_pid = dbg->pid;
	int prev_tid = dbg->tid;

	// Set dbg tid to the new child temporarily
	dbg->pid = dbg->forked_pid;
	dbg->tid = dbg->forked_pid;
	r_debug_select (dbg, dbg->forked_pid, dbg->forked_pid);
#if __i386__ || __x86_64__
	RListIter *iter;
	RBreakpointItem *b;
	// Unset all hw breakpoints in the child process
	r_debug_reg_sync (dbg, R_REG_TYPE_DRX, false);
	r_list_foreach (dbg->bp->bps, iter, b) {
		r_debug_drx_unset (dbg, r_bp_get_index_at (dbg->bp, b->addr));
	}
	r_debug_reg_sync (dbg, R_REG_TYPE_DRX, true);
#endif
	// Unset software breakpoints in the child process
	r_debug_bp_update (dbg);
	r_bp_restore (dbg->bp, false);

	// Return to the parent
	dbg->pid = prev_pid;
	dbg->tid = prev_tid;
	r_debug_select (dbg, dbg->pid, dbg->pid);

	// Restore sw breakpoints in the parent
	r_bp_restore (dbg->bp, true);
}

#ifdef PT_GETEVENTMSG
/*
 * @brief Handle PTRACE_EVENT_* when receiving SIGTRAP
 *
 * @param dowait Do waitpid to consume any signal in the newly created task
 * @return RDebugReasonType,
 * - R_DEBUG_REASON_UNKNOWN if the ptrace_event cannot be handled,
 * - R_DEBUG_REASON_ERROR if a ptrace command failed.
 *
 * NOTE: This API was added in Linux 2.5.46
 */
RDebugReasonType linux_ptrace_event (RDebug *dbg, int ptid, int status, bool dowait) {
	ut32 pt_evt;
#if __powerpc64__ || __arm64__ || __aarch64__ || __x86_64__
	ut64 data;
#else
	ut32 data;
#endif
	/* we only handle stops with SIGTRAP here */
	if (!WIFSTOPPED (status) || WSTOPSIG (status) != SIGTRAP) {
		return R_DEBUG_REASON_UNKNOWN;
	}

	pt_evt = status >> 16;
	switch (pt_evt) {
	case 0:
		/* NOTE: this case is handled by linux_handle_signals */
		break;
	case PTRACE_EVENT_CLONE:
		// Get the tid of the new thread
		if (r_debug_ptrace (dbg, PTRACE_GETEVENTMSG, ptid, 0, (r_ptrace_data_t)(size_t)&data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		if (dowait) {
			// The new child has a pending SIGSTOP.  We can't affect it until it
			// hits the SIGSTOP, but we're already attached.  */
			if (waitpid ((int)data, &status, 0) == -1) {
				r_sys_perror ("waitpid");
			}
		}

		linux_add_new_thread (dbg, (int)data);
		if (dbg->options.trace_clone) {
			r_debug_select (dbg, dbg->pid, (int)data);
		}
		eprintf ("(%d) Created thread %d\n", ptid, (int)data);
		return R_DEBUG_REASON_NEW_TID;
	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_FORK:
		// Get the pid of the new process
		if (r_debug_ptrace (dbg, PTRACE_GETEVENTMSG, ptid, 0, (r_ptrace_data_t)(size_t)&data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		dbg->forked_pid = data;
		if (dowait) {
			// The new child has a pending SIGSTOP. We can't affect it until it
			// hits the SIGSTOP, but we're already attached.  */
			if (waitpid (dbg->forked_pid, &status, 0) == -1) {
				r_sys_perror ("waitpid");
			}
		}
		eprintf ("(%d) Created process %d\n", ptid, (int)data);
		if (!dbg->options.trace_forks) {
			// We need to do this even if the new process will be detached since the
			// breakpoints are inherited from the parent
			linux_remove_fork_bps (dbg);
			if (r_debug_ptrace (dbg, PTRACE_DETACH, dbg->forked_pid, NULL, (r_ptrace_data_t)(size_t)NULL) == -1) {
				r_sys_perror ("PTRACE_DETACH");
			}
		}
		return R_DEBUG_REASON_NEW_PID;
	case PTRACE_EVENT_EXIT:
		// Get the exit status of the exiting task
		if (r_debug_ptrace (dbg, PTRACE_GETEVENTMSG, ptid, 0, (r_ptrace_data_t)(size_t)&data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		//TODO: Check other processes exit if dbg->options.trace_forks is on
		if (ptid != dbg->pid) {
			eprintf ("(%d) Thread exited with status=0x%"PFMT64x"\n", ptid, (ut64)data);
			return R_DEBUG_REASON_EXIT_TID;
		} else {
			eprintf ("(%d) Process exited with status=0x%"PFMT64x"\n", ptid, (ut64)data);
			return R_DEBUG_REASON_EXIT_PID;
		}
	default:
		eprintf ("Unknown PTRACE_EVENT encountered: %d\n", pt_evt);
		break;
	}
	return R_DEBUG_REASON_UNKNOWN;
}
#endif

/*
 * @brief Search for the parent of the newly created task and
 * handle the pending SIGTRAP with PTRACE_EVENT_*
 *
 * @param tid, TID of the new task
 * @return RDebugReasonType, Debug reason
 */
static RDebugReasonType linux_handle_new_task(RDebug *dbg, int tid) {
	int ret, status;
	if (dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		// Search for SIGTRAP with PTRACE_EVENT_* in other threads.
		r_list_foreach (dbg->threads, it, th) {
			if (th->pid == tid) {
				continue;
			}
			// Retrieve the signal without consuming it with PTRACE_GETSIGINFO
			siginfo_t siginfo = {0};
			ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, th->pid, 0, (r_ptrace_data_t)(size_t)&siginfo);
			// Skip if PTRACE_GETSIGINFO fails when the thread is running.
			if (ret == -1) {
				continue;
			}
#ifdef PT_GETEVENTMSG
			// NOTE: This API was added in Linux 2.5.46
			if (siginfo.si_signo == SIGTRAP) {
				// si_code = (SIGTRAP | PTRACE_EVENT_* << 8)
				int pt_evt = siginfo.si_code >> 8;
				// Handle PTRACE_EVENT_* that creates a new task (fork/clone)
				switch (pt_evt) {
				case PTRACE_EVENT_CLONE:
				case PTRACE_EVENT_VFORK:
				case PTRACE_EVENT_FORK:
					ret = waitpid (th->pid, &status, 0);
					return linux_ptrace_event (dbg, ret, status, false);
				default:
					break;
				}
			}
#endif
		}
	}
	return R_DEBUG_REASON_UNKNOWN;
}

int linux_step(RDebug *dbg) {
	int ret = false;
	int pid = dbg->tid;
	ret = r_debug_ptrace (dbg, PTRACE_SINGLESTEP, pid, 0, 0);
	if (ret == -1) {
		r_sys_perror ("native-singlestep");
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}

bool linux_set_options(RDebug *dbg, int pid) {
	int traceflags = 0;
	traceflags |= PTRACE_O_TRACEFORK;
	traceflags |= PTRACE_O_TRACEVFORK;
	traceflags |= PTRACE_O_TRACECLONE;
	if (dbg->options.trace_forks) {
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->options.trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	if (dbg->options.trace_aftersyscall) {
		traceflags |= PTRACE_O_TRACEEXIT;
	}
	/* SIGTRAP | 0x80 on signal handler .. not supported on all archs */
	traceflags |= PTRACE_O_TRACESYSGOOD;
	RCore *core = dbg->coreb.core;

	// PTRACE_SETOPTIONS can fail because of the asynchronous nature of ptrace
	// If the target is traced, the loop will always end with success
	while (r_debug_ptrace (dbg, PTRACE_SETOPTIONS, pid, 0, (r_ptrace_data_t)(size_t)traceflags) == -1) {
		void *bed = r_cons_sleep_begin (core->cons);
		usleep (1000);
		r_cons_sleep_end (core->cons, bed);
	}
	return true;
}

static void linux_detach_all(RDebug *dbg) {
	RList *th_list = dbg->threads;
	if (th_list) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (th_list, it, th) {
			if (th->pid != dbg->main_pid) {
				if (r_debug_ptrace (dbg, PTRACE_DETACH, th->pid, NULL, (r_ptrace_data_t)(size_t)NULL) == -1) {
					r_sys_perror ("PTRACE_DETACH");
				}
			}
		}
	}

	// Detaching from main proc
	if (r_debug_ptrace (dbg, PTRACE_DETACH, dbg->main_pid, NULL, (r_ptrace_data_t)(size_t)NULL) == -1) {
		r_sys_perror ("PTRACE_DETACH");
	}
}

static void linux_remove_thread(RDebug *dbg, int tid) {
	if (dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (dbg->threads, it, th) {
			if (th->pid == tid) {
				r_list_delete (dbg->threads, it);
				dbg->n_threads--;
				break;
			}
		}
	}
}

bool linux_select(RDebug *dbg, int pid, int tid) {
	if (dbg->pid != -1 && dbg->pid != pid) {
		return linux_attach_new_process (dbg, pid);
	}
	return linux_attach (dbg, tid);
}

bool linux_attach_new_process(RDebug *dbg, int pid) {
	linux_detach_all (dbg);
	if (dbg->threads) {
		r_list_free (dbg->threads);
		dbg->threads = NULL;
	}

	if (!linux_attach (dbg, pid)) {
		return false;
	}

	// Call select to syncrhonize the thread's data.
	dbg->pid = pid;
	dbg->tid = pid;
	r_debug_select (dbg, pid, pid);

	return true;
}

static void linux_dbg_wait_break_main(RDebug *dbg) {
	// Get the debugger and debuggee process group ID
	pid_t dpgid = getpgid (0);
	if (dpgid == -1) {
		r_sys_perror ("getpgid");
		return;
	}
	pid_t tpgid = getpgid (dbg->pid);
	if (tpgid == -1) {
		r_sys_perror ("getpgid");
		return;
	}

	// If the debuggee process is created by the debugger, do nothing because
	// SIGINT is already sent to both the debugger and debuggee in the same
	// process group.

	// If the debuggee is attached by the debugger, send SIGINT to the debuggee
	// in another process group.
	if (dpgid != tpgid) {
		if (!linux_kill_thread (dbg->pid, SIGINT)) {
			R_LOG_ERROR ("Could not interrupt pid (%d)", dbg->pid);
		}
	}
}

static void linux_dbg_wait_break(RDebug *dbg) {
	if (!linux_kill_thread (dbg->pid, SIGINT)) {
		R_LOG_ERROR ("Could not interrupt pid (%d)", dbg->pid);
	}
}

RDebugReasonType linux_dbg_wait(RDebug *dbg, int pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
	int tid = pid;
	int status, flags = __WALL;
	int ret = -1;

	if (pid == -1) {
		flags |= WNOHANG;
	}

	for (;;) {
		// In the main context, SIGINT is propagated to the debuggee if it is
		// in the same process group. Otherwise, the task is running in
		// background and SIGINT will not be propagated to the debuggee.
		RCore *core = dbg->coreb.core;
		const bool is_main = r_cons_context_is_main (core->cons, core->cons->context);
		if (is_main) {
			r_cons_break_push (core->cons, (RConsBreak)linux_dbg_wait_break_main, dbg);
		} else {
			r_cons_break_push (core->cons, (RConsBreak)linux_dbg_wait_break, dbg);
		}
		void *bed = r_cons_sleep_begin (core->cons);
		if (dbg->options.continue_all_threads) {
			ret = waitpid (-1, &status, flags);
		} else {
			ret = waitpid (pid, &status, flags);
		}
		r_cons_sleep_end (core->cons, bed);
		r_cons_break_pop (core->cons);

		if (ret < 0) {
			// Continue when interrupted by user;
			if (errno == EINTR) {
				continue;
			}
			r_sys_perror ("waitpid");
			break;
		} else if (ret == 0) {
			// Unset WNOHANG to call next waitpid in blocking mode.
			flags &= ~WNOHANG;
		} else {
			tid = ret;

			if (is_syscall_stop (status)) {
				if (syscall_handle_stop (dbg, tid)) {
					continue;
				}
				if (syscall_hooks_suppressed (dbg)) {
					dbg->reason.type = R_DEBUG_REASON_STEP;
					dbg->reason.signum = SIGTRAP;
					reason = dbg->reason.type;
					break;
				}
				if (syscall_resume (dbg, tid, false)) {
					continue;
				}
				reason = R_DEBUG_REASON_ERROR;
				break;
			}

			// Handle SIGTRAP with PTRACE_EVENT_*
			reason = linux_ptrace_event (dbg, tid, status, true);
			if (reason != R_DEBUG_REASON_UNKNOWN) {
				break;
			}

			if (WIFEXITED (status)) {
				if (tid == dbg->main_pid) {
					r_list_free (dbg->threads);
					dbg->threads = NULL;
					reason = R_DEBUG_REASON_DEAD;
					eprintf ("(%d) Process terminated with status %d\n", tid, WEXITSTATUS (status));
					break;
				} else {
					eprintf ("(%d) Child terminated with status %d\n", tid, WEXITSTATUS (status));
					linux_remove_thread (dbg, tid);
					continue;
				}
			} else if (WIFSIGNALED (status)) {
				eprintf ("child received signal %d\n", WTERMSIG (status));
				reason = R_DEBUG_REASON_SIGNAL;
			} else if (WIFSTOPPED (status)) {
				// If tid is not in the thread list and stopped by SIGSTOP,
				// handle it as a new task.
				if (!r_list_find (dbg->threads, &tid, &match_pid) &&
					WSTOPSIG (status) == SIGSTOP) {
					reason = linux_handle_new_task (dbg, tid);
					if (reason != R_DEBUG_REASON_UNKNOWN) {
						break;
					}
				}

				if (linux_handle_signals (dbg, tid)) {
					reason = dbg->reason.type;
				} else {
					eprintf ("can't handle signals\n");
					return R_DEBUG_REASON_ERROR;
				}
#ifdef WIFCONTINUED
			} else if (WIFCONTINUED (status)) {
				eprintf ("child continued...\n");
				reason = R_DEBUG_REASON_NONE;
#endif
			} else if (status == 1) {
				eprintf ("EEK DEAD DEBUGEE!\n");
				reason = R_DEBUG_REASON_DEAD;
			} else if (status == 0) {
				eprintf ("STATUS=0?!?!?!?\n");
				reason = R_DEBUG_REASON_DEAD;
			} else {
				if (ret != tid) {
					reason = R_DEBUG_REASON_NEW_PID;
				} else {
					eprintf ("CRAP. returning from wait without knowing why...\n");
				}
			}
			if (reason != R_DEBUG_REASON_UNKNOWN) {
				break;
			}
		}
	}
#if __aarch64__ || __arm64__
	const int vl = R_SYS_BITS_CHECK (dbg->bits, 64)? linux_sve_vl (dbg): 0;
	if (vl && vl != native_vector_width (dbg->reg, "z0") / 8) {
		char *profile = linux_reg_profile (dbg);
		r_reg_set_profile_string (dbg->reg, profile);
		free (profile);
	}
#endif
	dbg->reason.tid = tid;
	return reason;
}

int match_pid(const void *pid_o, const void *th_o) {
	int pid = *(int *)pid_o;
	RDebugPid *th = (RDebugPid *)th_o;
	return (pid == th->pid)? 0 : 1;
}

static void linux_add_new_thread(RDebug *dbg, int tid) {
	int uid = getuid(); // XXX
	char info[1024] = {0};
	RDebugPid *tid_info;

	if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
		tid_info = fill_pid_info (info, NULL, tid);
	} else {
		tid_info = r_debug_pid_new ("new_path", tid, uid, 's', 0);
	}
	linux_set_options (dbg, tid);
	r_list_append (dbg->threads, tid_info);
	dbg->n_threads++;
}

static bool linux_kill_thread(int tid, int signo) {
	int ret = syscall (__NR_tkill, tid, signo);

	if (ret == -1) {
		r_sys_perror ("tkill");
		return false;
	}

	return true;
}

static bool linux_stop_thread(RDebug *dbg, int tid) {
	int status, ret;
	siginfo_t siginfo = {0};

	// Return if the thread is already stopped
	ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, tid, 0,
		(r_ptrace_data_t) (intptr_t)&siginfo);
	if (ret == 0) {
		return true;
	}

	if (linux_kill_thread (tid, SIGSTOP)) {
		if ((ret = waitpid (tid, &status, 0)) == -1) {
			r_sys_perror ("waitpid");
		}
		return ret == tid;
	}
	return false;
}

bool linux_stop_threads(RDebug *dbg, int except) {
	bool ret = true;
	if (dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (dbg->threads, it, th) {
			if (th->pid && th->pid != except) {
				if (!linux_stop_thread (dbg, th->pid)) {
					ret = false;
				}
			}
		}
	}
	return ret;
}

static bool linux_attach_single_pid(RDebug *dbg, int pid) {
	siginfo_t sig = {0};

	if (pid < 0) {
		return false;
	}

	// Safely check if the PID has already been attached to avoid printing errors.
	// Attaching to a process that has already been started with PTRACE_TRACEME.
	// sets errno to "Operation not permitted" which may be misleading.
	// GETSIGINFO can be called multiple times and would fail without attachment.
	if (r_debug_ptrace (dbg, PTRACE_GETSIGINFO, pid, NULL,
		(r_ptrace_data_t)&sig) == -1) {
		// TODO: PTRACE_SEIZE enables PTRACE_INTERRUPT, but wont stop on attach
		if (r_debug_ptrace (dbg, PTRACE_ATTACH, pid, NULL, NULL) == -1) {
			r_sys_perror ("ptrace (PT_ATTACH)");
			return false;
		}

		// Make sure SIGSTOP is delivered and wait for it since we can't affect the pid
		// until it hits SIGSTOP.
		if (!linux_stop_thread (dbg, pid)) {
			R_LOG_ERROR ("Could not stop pid (%d)", pid);
			return false;
		}
	}

	if (!linux_set_options (dbg, pid)) {
		R_LOG_ERROR("failed set_options on %d", pid);
		return false;
	}
	dbg->pid = pid;
	return true;
}

static RList *get_pid_thread_list(RDebug *dbg, int main_pid) {
	RList *list = r_list_new ();
	if (R_LIKELY (list)) {
		list = linux_thread_list (dbg, main_pid, list);
		dbg->main_pid = main_pid;
	}
	return list;
}

bool linux_attach(RDebug *dbg, int pid) {
	if (!dbg->threads) {
		dbg->threads = get_pid_thread_list (dbg, pid);
		if (dbg->threads) {
			dbg->pid = pid;
		}
	} else {
		if (!r_list_find (dbg->threads, &pid, &match_pid)) {
			linux_attach_single_pid (dbg, pid);
		}
	}
	return true;
}

static char *read_link(int pid, const char *file) {
	char path[1024] = {0};
	char buf[1024] = {0};

	snprintf (path, sizeof (path), "/proc/%d/%s", pid, file);
	int ret = readlink (path, buf, sizeof (buf));
	if (ret > 0) {
		buf[sizeof (buf) - 1] = '\0';
		return strdup (buf);
	}
	return NULL;
}

RDebugInfo *linux_info(RDebug *dbg, const char *arg) {
	char proc_buff[1024];
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);

	RList *th_list;
	bool list_alloc = false;
	if (dbg->threads) {
		th_list = dbg->threads;
	} else {
		th_list = r_list_new ();
		list_alloc = true;
		if (th_list) {
			th_list = linux_thread_list (dbg, dbg->pid, th_list);
		}
	}
	RDebugPid *th;
	RListIter *it;
	bool found = false;
	r_list_foreach (th_list, it, th) {
		if (th->pid == dbg->pid) {
			found = true;
			break;
		}
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = found ? th->uid : -1;
	rdi->gid = found ? th->gid : -1;
	rdi->cwd = read_link (rdi->pid, "cwd");
	rdi->exe = read_link (rdi->pid, "exe");
	snprintf (proc_buff, sizeof (proc_buff), "/proc/%d/cmdline", rdi->pid);
	rdi->cmdline = r_file_slurp (proc_buff, NULL);
	snprintf (proc_buff, sizeof (proc_buff), "/proc/%d/stack", rdi->pid);
	rdi->kernel_stack = r_file_slurp (proc_buff, NULL);
	rdi->status = found ? th->status : R_DBG_PROC_STOP;
	if (list_alloc) {
		r_list_free (th_list);
	}
	return rdi;
}

RDebugPid *fill_pid_info(const char *info, const char *path, int tid) {
	RDebugPid *pid_info = R_NEW0 (RDebugPid);
	const char *ptr = strstr (info, "State:");
	if (ptr) {
		switch (*(ptr + 7)) {
		case 'R':
			pid_info->status = R_DBG_PROC_RUN;
			break;
		case 'S':
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		case 'T':
		case 't':
			pid_info->status = R_DBG_PROC_STOP;
			break;
		case 'Z':
			pid_info->status = R_DBG_PROC_ZOMBIE;
			break;
		case 'X':
			pid_info->status = R_DBG_PROC_DEAD;
			break;
		default:
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		}
	}
	ptr = strstr (info, "PPid:");
	if (ptr) {
		pid_info->ppid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Uid:");
	if (ptr) {
		pid_info->uid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Gid:");
	if (ptr) {
		pid_info->gid = atoi (ptr + 5);
	}

	pid_info->pid = tid;
	pid_info->path = path ? strdup (path) : NULL;
	pid_info->runnable = true;
	pid_info->pc = 0;
	return pid_info;
}

RList *linux_pid_list(int pid, RList *list) {
	list->free = (RListFree)&r_debug_pid_free;
	DIR *dh = NULL;
	struct dirent *de = NULL;
	char path[PATH_MAX], info[PATH_MAX];
	int i = -1;
	RDebugPid *pid_info = NULL;
	dh = opendir ("/proc");
	if (!dh) {
		r_sys_perror ("opendir /proc");
		r_list_free (list);
		return NULL;
	}
	while ((de = readdir (dh))) {
		path[0] = 0;
		info[0] = 0;
		// For each existing pid file
		if ((i = atoi (de->d_name)) <= 0) {
			continue;
		}

		procfs_pid_slurp (i, "cmdline", path, sizeof (path));
		if (!procfs_pid_slurp (i, "status", info, sizeof (info))) {
			// Get information about pid (status, pc, etc.)
			pid_info = fill_pid_info (info, path, i);
		} else {
			pid_info = r_debug_pid_new (path, i, 0, R_DBG_PROC_STOP, 0);
		}
		// Unless pid 0 is requested, only add the requested pid and it's child processes
		if (0 == pid || i == pid || pid_info->ppid == pid) {
			r_list_append (list, pid_info);
		} else {
			r_debug_pid_free (pid_info);
		}
	}
	closedir (dh);
	return list;
}

RList *linux_thread_list(RDebug *dbg, int pid, RList *list) {
	int i = 0, thid = 0;
	char *ptr, buf[PATH_MAX];
	RDebugPid *pid_info = NULL;
	ut64 pc = 0;
	if (pid < 1) {
		r_list_free (list);
		return NULL;
	}
	if (dbg->tid < 1) {
		dbg->tid = pid;
		dbg->pid = pid;
	}
	int prev_pid = dbg->pid;
	int prev_tid = dbg->tid;
	dbg->pid = pid;
	dbg->tid = pid;

	list->free = (RListFree)&r_debug_pid_free;
	/* if this process has a task directory, use that */
	snprintf (buf, sizeof (buf), "/proc/%d/task", pid);
	if (r_file_is_directory (buf)) {
		struct dirent *de;
		DIR *dh = opendir (buf);
		// Update the process' memory maps to set correct paths
		dbg->pid = pid;
		dbg->coreb.syncDebugMaps (dbg->coreb.core);
		while ((de = readdir (dh))) {
			if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) {
				continue;
			}
			int tid = atoi (de->d_name);
			char info[PATH_MAX];
			int uid = 0;
			if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
				ptr = strstr (info, "Uid:");
				if (ptr) {
					uid = atoi (ptr + 4);
				}
				ptr = strstr (info, "Tgid:");
				if (ptr) {
					int tgid = atoi (ptr + 5);
					if (tgid != pid) {
						/* Ignore threads that aren't in the pid's thread group */
						continue;
					}
				}
			}

			// Switch to the currently inspected thread to get it's program counter
			if (dbg->tid != tid) {
				linux_attach_single_pid (dbg, tid);
				dbg->tid = tid;
			}

			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
			pc = r_debug_reg_get (dbg, "PC");

			if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
				// Get information about pid (status, pc, etc.)
				pid_info = fill_pid_info (info, NULL, tid);
				pid_info->pc = pc;
			} else {
				pid_info = r_debug_pid_new (NULL, tid, uid, 's', pc);
			}
			r_list_append (list, pid_info);
			dbg->n_threads++;
		}
		closedir (dh);
		// Return to the original thread
		linux_attach_single_pid (dbg, prev_tid);
		dbg->pid = prev_pid;
		dbg->tid = prev_tid;
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	} else {
		/* Some linux configurations might hide threads from /proc, use this workaround instead */
#undef MAXPID
#define MAXPID 99999
		/* otherwise, brute force the pids */
		for (i = pid; i < MAXPID; i++) { // XXX
			if (procfs_pid_slurp (i, "status", buf, sizeof (buf)) == -1) {
				continue;
			}
			int uid = 0;
			/* look for a thread group id */
			ptr = strstr (buf, "Uid:");
			if (ptr) {
				uid = atoi (ptr + 4);
			}
			ptr = strstr (buf, "Tgid:");
			if (ptr) {
				int tgid = atoi (ptr + 5);

				/* if it is not in our thread group, we don't want it */
				if (tgid != pid) {
					continue;
				}

				if (procfs_pid_slurp (i, "comm", buf, sizeof (buf)) == -1) {
					/* fall back to auto-id */
					snprintf (buf, sizeof (buf), "thread_%d", thid++);
				}
				r_list_append (list, r_debug_pid_new (buf, i, uid, 's', 0));
			}
		}
	}
	return list;
}

bool linux_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	int pid = dbg->tid;
	if (pid == -1) {
		if (dbg->pid == -1) {
			R_LOG_ERROR ("Invalid pid %d", pid);
			return false;
		}
		pid = dbg->pid;
	}
	int ret = 0;
#if __x86_64__ || __aarch64__ || __arm64__
	if (type == R_REG_TYPE_FPU || (type >= R_REG_TYPE_VEC64 && type <= R_REG_TYPE_VEC512)) {
		return linux_vector_regs (dbg, buf, size, false);
	}
#endif
	switch (type) {
	case R_REG_TYPE_DRX:
#if __POWERPC__
		// no drx for powerpc
		return false;
#elif __i386__ || __x86_64__
#if !__ANDROID__
	{
		int i;
		for (i = 0; i < 8; i++) { //DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			long ret = r_debug_ptrace (dbg, PTRACE_PEEKUSER, pid,
					(void *)r_offsetof (struct user, u_debugreg[i]), 0);
			if ((i + 1) * sizeof (ret) > size) {
				R_LOG_ERROR ("Buffer of %d is too small for ptrace.peekuser", size);
				break;
			}
			memcpy (buf + (i * sizeof (ret)), &ret, sizeof (ret));
		}
		struct user a;
		return sizeof (a.u_debugreg);
	}
#else
	#warning Android X86 does not support DRX
#endif
#endif
		return true;
		break;
#if !(__x86_64__ || __aarch64__ || __arm64__)
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_VEC64: // MMX
	case R_REG_TYPE_VEC128: // XMM
		{
#if __x86_64__ || __i386__
		struct user_fpregs_struct fpregs;
		if (type == R_REG_TYPE_FPU) {
#if __i386__
#if !__ANDROID__
			struct user_fpxregs_struct fpxregs;
			ret = r_debug_ptrace (dbg, PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret == 0) {
				size = R_MIN (sizeof (fpxregs), size);
				memcpy (buf, &fpxregs, size);
				return size;
			} else {
				ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (ret != 0) {
					r_sys_perror ("PTRACE_GETFPREGS");
					return false;
				}
				size = R_MIN (sizeof (fpregs), size);
				memcpy (buf, &fpregs, size);
				return size;
			}
#else
			ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (ret != 0) {
				r_sys_perror ("PTRACE_GETFPREGS");
				return false;
			}
			size = R_MIN (sizeof (fpregs), size);
			memcpy (buf, &fpregs, size);
			return size;
#endif // !__ANDROID__
#endif // __i386__
		}
		return size;
#else
	#warning getfpregs not implemented for this platform
#endif
		}
		break;
#endif
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
			R_DEBUG_REG_T regs;
			memset (&regs, 0, sizeof (regs));
			memset (buf, 0, size);
#if (__arm64__ || __aarch64__ || __s390x__) && defined(PTRACE_GETREGSET)
			struct iovec io = {
				.iov_base = &regs,
				.iov_len = sizeof (regs)
			};
			ret = r_debug_ptrace (dbg, PTRACE_GETREGSET, pid, (void*)(size_t)1, &io);
			// ret = ptrace (PTRACE_GETREGSET, pid, (void*)(size_t)(NT_PRSTATUS), NULL); // &io);
#elif R2__BSD__ && (__POWERPC__ || __sparc__)
			ret = r_debug_ptrace (dbg, PTRACE_GETREGS, pid, &regs, NULL);
#elif __riscv
			// theres no PTRACE_GETREGS implemented for rv64
			struct iovec iov;
			iov.iov_base = &regs;
			iov.iov_len = sizeof (regs);
			ret = ptrace (PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
#else
			/* linux -{arm/mips/x86/x86_64} */
			ret = r_debug_ptrace (dbg, PTRACE_GETREGS, pid, NULL, &regs);
#endif
			/*
			 * if perror here says 'no such process' and the
			 * process exists still.. is because there's a missing call
			 * to 'wait'. and the process is not yet available to accept
			 * more ptrace queries.
			 */
			if (ret != 0) {
				r_sys_perror ("PTRACE_GETREGS");
				return false;
			}
			size = R_MIN (sizeof (regs), size);
			memcpy (buf, &regs, size);
			// r_print_hexdump (NULL, 0, buf, size, 16, 16, 0);
			return size;
		}
		break;
	}
	return false;
}

bool linux_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
#if __x86_64__ || __aarch64__ || __arm64__
	if (type == R_REG_TYPE_FPU || (type >= R_REG_TYPE_VEC64 && type <= R_REG_TYPE_VEC512)) {
		return linux_vector_regs (dbg, (ut8 *)buf, size, true);
	}
#endif
	int pid = dbg->tid;

	if (type == R_REG_TYPE_DRX) {
#if !__ANDROID__ && (__i386__ || __x86_64__)
		int i;
		long *val = (long*)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			if (r_debug_ptrace (dbg, PTRACE_POKEUSER, pid,
					(void *)r_offsetof (struct user, u_debugreg[i]), (r_ptrace_data_t)val[i])) {
				R_LOG_ERROR ("ptrace failed for dr %d", i);
				r_sys_perror ("ptrace POKEUSER");
			}
		}
		return sizeof (R_DEBUG_REG_T);
#else
		return false;
#endif
	}
	if (type == R_REG_TYPE_GPR) {
#if __arm64__ || __aarch64__ || __s390x__ || __riscv
		struct iovec io = {
			.iov_base = (void*)buf,
			.iov_len = sizeof (R_DEBUG_REG_T)
		};
		int ret = r_debug_ptrace (dbg, PTRACE_SETREGSET, pid, (void*)(size_t)NT_PRSTATUS, (r_ptrace_data_t)(size_t)&io);
#elif __POWERPC__ || __sparc__
		int ret = r_debug_ptrace (dbg, PTRACE_SETREGS, pid, buf, NULL);
#else
		int ret = r_debug_ptrace (dbg, PTRACE_SETREGS, pid, 0, (void*)buf);
#endif
#if DEAD_CODE
		if (size > sizeof (R_DEBUG_REG_T)) {
			size = sizeof (R_DEBUG_REG_T);
		}
#endif
		if (ret == -1) {
			r_sys_perror ("reg_write");
			return false;
		}
		return true;
	}
	if (type == R_REG_TYPE_FPU || type == R_REG_TYPE_VEC64 || type == R_REG_TYPE_VEC128) {
#if __i386__ || __x86_64__
		int ret = r_debug_ptrace (dbg, PTRACE_SETFPREGS, pid, 0, (void*)buf);
		return (ret != 0) ? false : true;
#endif
	}
	return false;
}

RList *linux_desc_list(int pid) {
	char path[512], buf[512];
	struct dirent *de;
	int type, perm;
	struct stat st;
	DIR *dd = NULL;

	snprintf (path, sizeof (path), "/proc/%i/fd/", pid);
	if (!(dd = opendir (path))) {
		r_sys_perror ("opendir /proc/x/fd");
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		closedir (dd);
		return NULL;
	}
	ret->free = (RListFree)r_debug_desc_free;
	while ((de = (struct dirent *)readdir (dd))) {
		if (de->d_name[0] == '.') {
			continue;
		}
		char *fn = r_str_newf ("/proc/%d/fd/%s", pid, de->d_name);
		memset (buf, 0, sizeof (buf));
		if (readlink (fn, buf, sizeof (buf) - 1) == -1) {
			r_list_free (ret);
			closedir (dd);
			free (fn);
			r_sys_perror ("readlink failure");
			return NULL;
		}
		buf[sizeof (buf) - 1] = 0;
		type = perm = 0;

		// Read file type
		if (stat (fn, &st) != -1) {
			bool isfifo = st.st_mode & S_IFIFO;
#ifdef S_IFSOCK
			/* Do *not* remove the == here. S_IFSOCK can be multiple
			 * bits, and we must match all of them. */
			bool issock = (st.st_mode & S_IFSOCK) == S_IFSOCK;
#endif
			bool ischr = st.st_mode & S_IFCHR;
			if (isfifo) {
				type = 'P';
#ifdef S_IFSOCK
			} else if (issock) {
				type = 'S';
#endif
			} else if (ischr) {
				type = 'C';
			} else {
				type = '-';
			}
		}
		// Read permissions // TOCTOU
		if (lstat (fn, &st) != -1) {
			if (st.st_mode & S_IRUSR) {
				perm |= R_PERM_R;
			}
			if (st.st_mode & S_IWUSR) {
				perm |= R_PERM_W;
			}
		}
		free (fn);
		// Get offset
		fn = r_str_newf ("/proc/%d/fdinfo/%s", pid, de->d_name);
		int f = open (fn, O_RDONLY);
		char fdinfo[512];
		fdinfo[0] = 0;
		if (f >= 0) {
			if (read (f, fdinfo, sizeof (fdinfo) - 1) < 0) {
				R_LOG_WARN ("failed to read %s", fn);
				close (f);
				r_list_free (ret);
				closedir (dd);
				free (fn);
				return NULL;
			}
			fdinfo[sizeof (fdinfo) - 1] = '\0';
			close (f);
		}
		free (fn);
		/* First line of fdinfo is "pos: [offset]" */
		ut64 offset = (int) r_num_math (NULL, r_str_trim_head_ro (fdinfo + 4));
		RDebugDesc *desc = r_debug_desc_new (atoi (de->d_name), buf, perm, type, offset);
		if (!desc) {
			break;
		}
		r_list_append (ret, desc);
	}
	closedir (dd);
	return ret;
}

#endif
