/* radare - LGPL - Copyright 2026 - pancake */

// Ptrace-invisible Linux process IO using /proc/[pid]/mem and eBPF uprobes.
// A small KPROBE program snapshots pt_regs into a BPF map when its uprobe hits.
// This is a tracing facility: it cannot single-step, pause, or redirect execution.

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>

#if defined(__riscv) && __riscv_xlen == 64
#define R2_EBPF_RISCV64 1
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__) || R2_EBPF_RISCV64) && defined(__has_include)
#if __has_include(<linux/bpf.h>) && __has_include(<linux/perf_event.h>)
#define HAVE_EBPF 1
#endif
#endif

#if __linux__

#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#if HAVE_EBPF
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

// Register names follow the leading GP fields in each architecture's pt_regs.
#if defined(__x86_64__)
static const char *const reg_names[] = {
	"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
	"rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
	"rsp", "ss"
};
#define REG_PC 16
#elif defined(__aarch64__)
static const char *const reg_names[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
	"x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
	"sp", "pc", "pstate"
};
#define REG_PC 32
#elif defined(R2_EBPF_RISCV64)
static const char *const reg_names[] = {
	"pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
	"t3", "t4", "t5", "t6"
};
#define REG_PC 0
#endif
#define REG_COUNT ((int)R_ARRAY_SIZE (reg_names))
#define REGBUF (REG_COUNT * sizeof (ut64))

static void print_snapshot(RIO *io, const ut64 *regs) {
	int i;
	for (i = 0; i < REG_COUNT; i++) {
		io->cb_printf ("%-8s 0x%016"PFMT64x"%s", reg_names[i], regs[i],
			(i % 3 == 2)? "\n": "  ");
	}
	if (i % 3 != 0) {
		io->cb_printf ("\n");
	}
}

static void emit_reg_flags(RIO *io, const ut64 *regs) {
	int i;
	io->cb_printf ("fs registers\n");
	for (i = 0; i < REG_COUNT; i++) {
		io->cb_printf ("f reg.%s 1 0x%"PFMT64x"\n", reg_names[i], regs[i]);
	}
	io->cb_printf ("fs *\n");
}
#endif

typedef struct {
	char *spawn_path;
	ut64 off;
	int mem_fd;
	int pid;
#if HAVE_EBPF
	int map_fd;
	int prog_fd;
	int perf_fd;
#endif
	bool spawned;
	bool child_reaped;
	bool writable;
} RIOEbpf;

#define RIOEBPF(x) ((RIOEbpf *)(x)->data)

static bool spawn_preexec(RIOEbpf *e);
static bool reap_spawned(RIOEbpf *e);

// /proc/pid/mem descriptors go stale when a spawned target calls execve.
static void reopen_mem(RIOEbpf *e) {
	char mempath[64];
	snprintf (mempath, sizeof (mempath), "/proc/%d/mem", e->pid);
	int fd = r_sandbox_open (mempath, e->writable? O_RDWR: O_RDONLY, 0);
	if (fd >= 0) {
		close (e->mem_fd);
		e->mem_fd = fd;
	}
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	RIOEbpf *e = RIOEBPF (desc);
	memset (buf, io->Oxff, len);
	if (e->mem_fd < 0 || (e->spawned && reap_spawned (e))) {
		return -1;
	}
	int r = pread (e->mem_fd, buf, len, (off_t)e->off);
	if (r < 0 && e->spawned && !reap_spawned (e)) {
		// stale fd after execve: reopen once and retry
		reopen_mem (e);
		r = pread (e->mem_fd, buf, len, (off_t)e->off);
	}
	return r;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int len) {
	RIOEbpf *e = RIOEBPF (desc);
	if (e->mem_fd < 0 || (e->spawned && reap_spawned (e))) {
		return -1;
	}
	int r = pwrite (e->mem_fd, buf, len, (off_t)e->off);
	if (r < 0 && e->spawned && !reap_spawned (e)) {
		reopen_mem (e);
		r = pwrite (e->mem_fd, buf, len, (off_t)e->off);
	}
	return r;
}

static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	RIOEbpf *e = RIOEBPF (desc);
	switch (whence) {
	case R_IO_SEEK_SET: e->off = offset; break;
	case R_IO_SEEK_CUR: e->off += offset; break;
	case R_IO_SEEK_END: e->off = UT64_MAX; break;
	}
	return e->off;
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "ebpf://");
}

#if HAVE_EBPF
static int bpf_(int cmd, union bpf_attr *attr) {
	return syscall (__NR_bpf, cmd, attr, sizeof (*attr));
}

static int ebpf_map(ut32 value_size) {
	union bpf_attr attr = {0};
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof (ut32);
	attr.value_size = value_size;
	attr.max_entries = 1;
	return bpf_ (BPF_MAP_CREATE, &attr);
}

// Test syscall availability; probe setup reports permission failures later.
static bool ebpf_available(void) {
	int fd = ebpf_map (sizeof (ut32));
	bool available = fd >= 0 || errno != ENOSYS;
	if (fd >= 0) {
		close (fd);
	}
	return available;
}

// Copy the uprobe's pt_regs context into map slot 0 via bpf_probe_read.
static int ebpf_load_snapshot_prog(int map_fd) {
	const struct bpf_insn prog[] = {
		// r6 = ctx (pt_regs pointer)
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_6, .src_reg = BPF_REG_1 },
		// key 0 on the stack: *(u32 *)(r10 - 4) = 0
		{ .code = BPF_ST | BPF_MEM | BPF_W, .dst_reg = BPF_REG_10, .off = -4, .imm = 0 },
		// r2 = r10 - 4  (&key)
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_2, .src_reg = BPF_REG_10 },
		{ .code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = BPF_REG_2, .imm = -4 },
		// r1 = map_fd  (BPF_LD_MAP_FD is a wide, two-slot instruction)
		{ .code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .imm = map_fd },
		{ .code = 0 },
		// r0 = map_lookup_elem(r1, r2)
		{ .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_map_lookup_elem },
		// if r0 == 0 goto exit (skip the 4 setup insns below)
		{ .code = BPF_JMP | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_0, .off = 4, .imm = 0 },
		// r1 = value ptr (dst)
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_0 },
		// r2 = REGBUF (len)
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_2, .imm = REGBUF },
		// r3 = r6 (src = pt_regs)
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_3, .src_reg = BPF_REG_6 },
		// bpf_probe_read(dst, len, src)
		{ .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_probe_read },
		// r0 = 0; exit
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	union bpf_attr attr = {0};
	attr.prog_type = BPF_PROG_TYPE_KPROBE;
	attr.insns = (ut64)(size_t)prog;
	attr.insn_cnt = R_ARRAY_SIZE (prog);
	attr.license = (ut64)(size_t)"GPL"; // probe_read is a GPL-only helper
	// An undersized verifier log makes a valid program fail with ENOSPC.
	int fd = bpf_ (BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		// Retry genuine failures with a large diagnostic buffer.
		const size_t logsz = 1 << 16;
		char *log = calloc (1, logsz);
		if (log) {
			attr.log_level = 1;
			attr.log_buf = (ut64)(size_t)log;
			attr.log_size = logsz;
			fd = bpf_ (BPF_PROG_LOAD, &attr);
			if (fd < 0 && *log) {
				R_LOG_DEBUG ("bpf verifier: %s", log);
			}
			free (log);
		}
	}
	return fd;
}

static int uprobe_pmu_type(void) {
	// small sysfs file; r_file_slurp warns on the short read, so read it raw
	int fd = r_sandbox_open ("/sys/bus/event_source/devices/uprobe/type", O_RDONLY, 0);
	if (fd < 0) {
		return -1;
	}
	char buf[32] = {0};
	ssize_t n = read (fd, buf, sizeof (buf) - 1);
	close (fd);
	return (n > 0)? atoi (buf): -1;
}

// Translate a runtime address into the binary path and offset uprobes require.
static char *addr_to_file_offset(int pid, ut64 addr, ut64 *foff) {
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/maps", pid);
	char *maps = r_file_slurp (path, NULL);
	if (!maps) {
		return NULL;
	}
	char *ret = NULL;
	char *next = NULL;
	char *line;
	for (line = r_str_tok_r (maps, "\n", &next); line;
			line = r_str_tok_r (NULL, "\n", &next)) {
		ut64 start = 0, end = 0, off = 0;
		char perms[5] = {0};
		if (sscanf (line, "%"PFMT64x"-%"PFMT64x" %4s %"PFMT64x, &start, &end, perms, &off) != 4) {
			continue;
		}
		if (addr < start || addr >= end || perms[2] != 'x') {
			continue;
		}
		const char *map_path = strchr (line, '/');
		if (!map_path) {
			continue;
		}
		*foff = (addr - start) + off;
		ret = strdup (map_path);
		break;
	}
	free (maps);
	return ret;
}

static void ebpf_detach(RIOEbpf *e) {
	if (e->perf_fd >= 0) {
		ioctl (e->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
		close (e->perf_fd);
		e->perf_fd = -1;
	}
	if (e->prog_fd >= 0) {
		close (e->prog_fd);
		e->prog_fd = -1;
	}
}

static bool ebpf_probe(RIOEbpf *e, ut64 addr) {
	int ptype = uprobe_pmu_type ();
	if (ptype < 0) {
		R_LOG_ERROR ("Kernel has no uprobe PMU (need CONFIG_UPROBE_EVENTS)");
		return false;
	}
	// Pre-exec spawned targets use a raw file offset because they have no map yet.
	ut64 foff = 0;
	char *bin = addr_to_file_offset (e->pid, addr, &foff);
	if (!bin) {
		if (spawn_preexec (e)) {
			bin = strdup (e->spawn_path);
			foff = addr;
		} else {
			R_LOG_ERROR ("Cannot map 0x%"PFMT64x" to an executable file mapping", addr);
			return false;
		}
	}
	if (e->map_fd < 0) {
		e->map_fd = ebpf_map (REGBUF);
		if (e->map_fd < 0) {
			R_LOG_ERROR ("bpf map create failed (need root or CAP_BPF): %s", strerror (errno));
			free (bin);
			return false;
		}
	}
	int prog = ebpf_load_snapshot_prog (e->map_fd);
	if (prog < 0) {
		R_LOG_ERROR ("bpf prog load failed (need root or CAP_BPF): %s", strerror (errno));
		free (bin);
		return false;
	}
	struct perf_event_attr pe = {0};
	pe.type = ptype;
	pe.size = sizeof (pe);
	pe.config = 0; // 0 = uprobe entry (bit 0 would select uretprobe)
	pe.config1 = (ut64)(size_t)bin; // uprobe_path
	pe.config2 = foff; // probe_offset
	int perf = syscall (__NR_perf_event_open, &pe, e->pid, -1, -1, 0);
	if (perf < 0) {
		R_LOG_ERROR ("perf_event_open(uprobe) failed for %s+0x%"PFMT64x": %s",
			bin, foff, strerror (errno));
		close (prog);
		free (bin);
		return false;
	}
	if (ioctl (perf, PERF_EVENT_IOC_SET_BPF, prog) < 0 ||
			ioctl (perf, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		R_LOG_ERROR ("attaching bpf to uprobe failed: %s", strerror (errno));
		close (perf);
		close (prog);
		free (bin);
		return false;
	}
	ebpf_detach (e); // drop any previous probe, keep the map
	e->prog_fd = prog;
	e->perf_fd = perf;
	R_LOG_INFO ("uprobe armed at %s+0x%"PFMT64x" (run the target so it hits 0x%"PFMT64x")",
		bin, foff, addr);
	free (bin);
	return true;
}

static bool ebpf_read_regs(RIOEbpf *e, ut64 *regs) {
	if (e->map_fd < 0) {
		return false;
	}
	ut32 key = 0;
	union bpf_attr attr = {0};
	attr.map_fd = e->map_fd;
	attr.key = (ut64)(size_t)&key;
	attr.value = (ut64)(size_t)regs;
	return bpf_ (BPF_MAP_LOOKUP_ELEM, &attr) == 0;
}

// Return false before the first snapshot so callers can use the procfs fallback.
static bool ebpf_snapshot_regs(RIO *io, RIOEbpf *e) {
	ut64 r[REG_COUNT] = {0};
	if (!ebpf_read_regs (e, r) || r[REG_PC] == 0) {
		return false;
	}
	print_snapshot (io, r);
	return true;
}
#endif

// /proc/pid/syscall ends in the stopped task's stack and program counters.
static bool proc_pc_sp(int pid, ut64 *pc, ut64 *sp) {
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/syscall", pid);
	char *s = r_file_slurp (path, NULL);
	if (!s) {
		return false;
	}
	r_str_trim (s);
	const char *pcstr = r_str_rchr (s, NULL, ' ');
	const char *spstr = pcstr? r_str_rchr (s, pcstr - 1, ' '): NULL;
	bool ok = spstr && !r_str_startswith (s, "running");
	if (ok) {
		*pc = r_num_get (NULL, pcstr + 1);
		*sp = r_num_get (NULL, spstr + 1);
	}
	free (s);
	return ok;
}

// Prefer a full eBPF snapshot, then fall back to procfs pc/sp.
static void print_regs(RIO *io, RIOEbpf *e) {
#if HAVE_EBPF
	if (ebpf_snapshot_regs (io, e)) {
		return;
	}
#endif
	ut64 pc = 0, sp = 0;
	if (proc_pc_sp (e->pid, &pc, &sp)) {
		io->cb_printf ("pc 0x%016"PFMT64x"  sp 0x%016"PFMT64x"\n", pc, sp);
		io->cb_printf ("(pc/sp from /proc/%d/syscall; ':probe <addr>' captures the full set)\n", e->pid);
	} else {
		R_LOG_ERROR ("Cannot read registers: target is running (try ':stop' or ':contstop')");
	}
}

// Before execve, a spawned target's procfs state still belongs to the r2 stub.
static bool spawn_preexec(RIOEbpf *e) {
	if (!e->spawned || !e->spawn_path) {
		return false;
	}
	char *path = r_sys_pidpath (e->pid);
	if (!path) {
		return false;
	}
	bool preexec = strcmp (r_file_basename (path), r_file_basename (e->spawn_path)) != 0;
	free (path);
	return preexec;
}

static bool preexec_guard(RIOEbpf *e) {
	if (spawn_preexec (e)) {
		R_LOG_WARN ("target has not exec'd yet (pre-exec stub); run ':cont' or ':contstop' first");
		return true;
	}
	return false;
}

static void emit_maps(RIO *io, RIOEbpf *e, bool as_flags) {
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/maps", e->pid);
	char *m = r_file_slurp (path, NULL);
	if (!m) {
		R_LOG_ERROR ("Cannot read %s", path);
		return;
	}
	if (as_flags) {
		io->cb_printf ("fs maps\n");
	}
	char *next = NULL;
	char *line;
	int idx = 0;
	for (line = r_str_tok_r (m, "\n", &next); line;
			line = r_str_tok_r (NULL, "\n", &next)) {
		ut64 start = 0, end = 0;
		if (sscanf (line, "%"PFMT64x"-%"PFMT64x" %*7s", &start, &end) != 2) {
			continue;
		}
		if (!as_flags) {
			const char *rest = strchr (line, ' ');
			io->cb_printf ("0x%"PFMT64x" - 0x%"PFMT64x"%s\n", start, end, rest? rest: "");
			continue;
		}
		const char *map_path = strchr (line, '/');
		char *name = map_path? (char *)r_file_basename (map_path): NULL;
		if (name) {
			r_name_filter (name, -1);
		}
		io->cb_printf ("f map.%d.%s 0x%"PFMT64x" 0x%"PFMT64x"\n", idx++, name? name: "anon", end - start, start);
	}
	if (as_flags) {
		io->cb_printf ("fs *\n");
	}
	free (m);
}

// Emit an r2 script: flags for every memory mapping plus the register set.
static void emit_r2(RIO *io, RIOEbpf *e) {
	emit_maps (io, e, true);
#if HAVE_EBPF
	ut64 r[REG_COUNT] = {0};
	if (ebpf_read_regs (e, r) && r[REG_PC]) {
		emit_reg_flags (io, r);
		return;
	}
#endif
	ut64 pc = 0, sp = 0;
	if (proc_pc_sp (e->pid, &pc, &sp)) {
		io->cb_printf ("fs registers\nf reg.pc 1 0x%"PFMT64x"\nf reg.sp 1 0x%"PFMT64x"\nfs *\n", pc, sp);
	}
}

// Only spawned targets are waitable children; retry interrupted waits.
static pid_t wait_child(RIOEbpf *e, int options) {
	int status = 0;
	pid_t ret;
	do {
		ret = waitpid (e->pid, &status, options);
	} while (ret < 0 && errno == EINTR);
	if (ret == e->pid && !WIFSTOPPED (status)) {
		e->child_reaped = true;
	} else if (ret < 0) {
		if (errno == ECHILD) {
			e->child_reaped = true;
		} else {
			R_LOG_WARN ("waitpid(%d) failed: %s", e->pid, strerror (errno));
		}
	}
	return ret;
}

static bool reap_spawned(RIOEbpf *e) {
	if (e->spawned && !e->child_reaped) {
		wait_child (e, WNOHANG);
	}
	return e->child_reaped;
}

// Spawned children report stops through waitpid; attached PIDs require procfs.
static bool wait_stopped(RIOEbpf *e) {
	if (e->spawned) {
		return wait_child (e, WUNTRACED) == e->pid && !e->child_reaped;
	}
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/stat", e->pid);
	int i;
	for (i = 0; i < 1000; i++) {
		char *s = r_file_slurp (path, NULL);
		if (!s) {
			return false;
		}
		const char *p = r_str_rchr (s, NULL, ')');
		bool stopped = p && p[1] == ' ' && (p[2] == 'T' || p[2] == 't');
		free (s);
		if (stopped) {
			return true;
		}
		r_sys_usleep (1000);
	}
	return false;
}

static bool signal_target(RIOEbpf *e, int sig) {
	if (e->spawned && reap_spawned (e)) {
		return sig == SIGKILL;
	}
	if (kill (e->pid, sig) < 0) {
		int error = errno;
		if (e->spawned && error == ESRCH) {
			wait_child (e, 0);
			return e->child_reaped;
		}
		R_LOG_WARN ("Cannot signal pid %d: %s", e->pid, strerror (error));
		return false;
	}
	if (e->spawned && sig == SIGKILL) {
		wait_child (e, 0);
		return e->child_reaped;
	}
	return true;
}

static void stop_target(RIOEbpf *e) {
	if (!signal_target (e, SIGSTOP)) {
		return;
	}
	if (!wait_stopped (e)) {
		R_LOG_WARN ("Target did not stop (may have exited)");
		return;
	}
	reopen_mem (e);
}

// Spawn stopped before execve so probes can be armed without ptrace.
static int ebpf_spawn(const char *cmdline, char **path_out) {
	int argc = 0;
	char **argv = r_str_argv (cmdline, &argc);
	if (!argv || argc < 1) {
		r_str_argv_free (argv);
		return -1;
	}
	pid_t pid = fork ();
	if (pid < 0) {
		r_str_argv_free (argv);
		return -1;
	}
	if (pid == 0) {
		raise (SIGSTOP);
		execv (argv[0], argv);
		_exit (127);
	}
	*path_out = strdup (argv[0]);
	r_str_argv_free (argv);
	RIOEbpf child = { .pid = pid, .spawned = true };
	if (!wait_stopped (&child)) {
		R_LOG_ERROR ("Spawned pid %d did not stop", pid);
		if (!child.child_reaped) {
			signal_target (&child, SIGKILL);
		}
		return -1;
	}
	return pid;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (!__plugin_open (io, file, false)) {
		return NULL;
	}
	const char *arg = file + strlen ("ebpf://");
	char *spawn_path = NULL;
	bool spawned = strchr (arg, '/') != NULL;
	int pid = spawned? ebpf_spawn (arg, &spawn_path): atoi (arg);
	if (pid < 1) {
		R_LOG_ERROR ("Usage: r2 ebpf://[pid] or ebpf://[/path/to/bin args]");
		free (spawn_path);
		return NULL;
	}
	char mempath[64];
	snprintf (mempath, sizeof (mempath), "/proc/%d/mem", pid);
	bool writable = true;
	int mem_fd = r_sandbox_open (mempath, O_RDWR, 0);
	if (mem_fd < 0) {
		writable = false;
		mem_fd = r_sandbox_open (mempath, O_RDONLY, 0);
	}
	if (mem_fd < 0) {
		R_LOG_ERROR ("Cannot open %s (permission or no such pid)", mempath);
		if (spawned) {
			RIOEbpf child = { .pid = pid, .spawned = true };
			signal_target (&child, SIGKILL);
		}
		free (spawn_path);
		return NULL;
	}
	RIOEbpf *e = R_NEW0 (RIOEbpf);
	e->pid = pid;
	e->mem_fd = mem_fd;
	e->spawned = spawned;
	e->writable = writable;
	e->spawn_path = spawn_path;
	if (spawned) {
		R_LOG_INFO ("Spawned pid %d (stopped). ':probe <fileoffset>' then ':cont' to run", pid);
	}
#if HAVE_EBPF
	e->map_fd = e->prog_fd = e->perf_fd = -1;
	if (!ebpf_available ()) {
		R_LOG_WARN ("bpf() syscall unavailable: register snapshots disabled, memory io still works");
	}
#else
	R_LOG_WARN ("eBPF uprobe support not built for this arch: memory io and :regs (pc/sp) still work");
#endif
	int perm = R_PERM_RX | (writable? R_PERM_W: 0);
	RIODesc *d = r_io_desc_new (io, &r_io_plugin_ebpf, file, perm, mode, e);
	d->name = r_sys_pidpath (pid);
	return d;
}

static bool __close(RIODesc *desc) {
	RIOEbpf *e = RIOEBPF (desc);
#if HAVE_EBPF
	ebpf_detach (e);
	if (e->map_fd >= 0) {
		close (e->map_fd);
	}
#endif
	close (e->mem_fd);
	if (e->spawned) {
		signal_target (e, SIGKILL);
	}
	free (e->spawn_path);
	R_FREE (desc->data);
	return true;
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	RIOEbpf *e = RIOEBPF (desc);
	if (R_STR_ISEMPTY (cmd)) {
		return NULL;
	}
	bool child_exited = e->spawned && reap_spawned (e);
	if (child_exited && !r_str_startswith (cmd, "pid") &&
			!r_str_startswith (cmd, "kill") &&
			!r_str_startswith (cmd, "probe-") && cmd[0] != '?' &&
			!r_str_startswith (cmd, "help")) {
		R_LOG_WARN ("Spawned target %d has exited", e->pid);
		return NULL;
	}
	if (r_str_startswith (cmd, "pid")) {
		// pid stays the first token so scripts can still parse it
		char *exe = child_exited? NULL: r_sys_pidpath (e->pid);
		const char *state = child_exited? "exited": e->spawned? "spawned": "attached";
		io->cb_printf ("%d %s%s%s\n", e->pid, state,
			exe? " ": "", exe? exe: "");
		free (exe);
	} else if (r_str_startswith (cmd, "maps")) {
		if (!preexec_guard (e)) {
			emit_maps (io, e, false);
		}
	} else if (r_str_startswith (cmd, "r2")) {
		if (!preexec_guard (e)) {
			emit_r2 (io, e);
		}
	} else if (r_str_startswith (cmd, "contstop")) {
		const char *arg = r_str_trim_head_ro (cmd + strlen ("contstop"));
		ut64 ms = *arg? r_num_get (NULL, arg): 0;
		if (signal_target (e, SIGCONT)) {
			if (ms) {
				r_sys_usleep (ms * 1000);
			}
			if (!e->spawned || !reap_spawned (e)) {
				stop_target (e);
			}
		}
	} else if (r_str_startswith (cmd, "cont")) {
		signal_target (e, SIGCONT);
	} else if (r_str_startswith (cmd, "stop")) {
		stop_target (e);
	} else if (r_str_startswith (cmd, "kill")) {
		signal_target (e, SIGKILL);
	} else if (r_str_startswith (cmd, "regs") || !strcmp (cmd, "r")) {
		if (!preexec_guard (e)) {
			print_regs (io, e);
		}
#if HAVE_EBPF
	} else if (r_str_startswith (cmd, "probe-")) {
		ebpf_detach (e);
	} else if (r_str_startswith (cmd, "probe")) {
		const char *arg = r_str_trim_head_ro (cmd + strlen ("probe"));
		if (R_STR_ISEMPTY (arg)) {
			R_LOG_ERROR ("Usage: :probe <addr>");
		} else {
			ebpf_probe (e, r_num_get (NULL, arg));
		}
#endif
	} else {
		if (cmd[0] != '?' && !r_str_startswith (cmd, "help")) {
			R_LOG_ERROR ("Unknown ebpf command '%s'", cmd);
		}
		io->cb_printf (
			":pid            show target pid\n"
			":maps           dump /proc/pid/maps of the target\n"
			":r2             emit r2 flag commands for the maps and registers\n"
			":cont           SIGCONT the target (resume a spawned/stopped process)\n"
			":stop           SIGSTOP the target and wait until it is frozen\n"
			":contstop [ms]  resume then re-freeze after [ms] ms (unreliable 'step')\n"
			":kill           SIGKILL the target (and reap spawned children)\n"
			":regs           print registers (eBPF snapshot, else pc/sp from /proc)\n"
			":probe <addr>   arm an eBPF uprobe that snapshots full registers at addr\n"
			":probe-         remove the current uprobe\n"
			"note: memory read/write uses /proc/pid/mem (no ptrace, TracerPid stays 0)\n"
			"note: eBPF traces, it cannot step/pause the process nor rewrite its regs\n");
	}
	return NULL;
}

RIOPlugin r_io_plugin_ebpf = {
	.meta = {
		.name = "ebpf",
		.author = "pancake",
		.desc = "ptrace-invisible process io via /proc/pid/mem + eBPF uprobe reg snapshots",
		.license = "LGPL-3.0-only",
	},
	.uris = "ebpf://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.write = __write,
	.system = __system,
};

#else // !__linux__

RIOPlugin r_io_plugin_ebpf = {
	.meta = {
		.name = NULL
	},
};

#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ebpf,
	.version = R2_VERSION
};
#endif
