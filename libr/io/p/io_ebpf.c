/* radare - LGPL - Copyright 2026 - pancake */

// Alternative, ptrace-invisible process IO backend for Linux using eBPF.
//
// Memory read/write goes through /proc/[pid]/mem (no PTRACE_ATTACH, so the
// target's /proc/self/status TracerPid stays 0). The ':' system commands use a
// tiny hand-assembled eBPF KPROBE program attached as a uprobe to snapshot the
// CPU registers (struct pt_regs) into a BPF map when the probe is hit. This is a
// tracing facility, not a debugger: eBPF cannot single-step, cannot pause and
// hand control to userspace, and kernel uprobes cannot rewrite pt_regs to
// redirect execution. See ':?' for the available commands.

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

// The uprobe context is a struct pt_regs; we copy its leading GP fields into a
// map. The register names/order are arch-specific and match that layout, so a
// snapshot index maps directly to reg_names[]. REG_PC indexes the program
// counter, used to tell whether a snapshot has actually been captured.
#if defined(__x86_64__)
// x86_64 pt_regs: 21 u64 fields (168 bytes).
static const char *const reg_names[] = {
	"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
	"rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
	"rsp", "ss"
};
#define REG_PC 16
#elif defined(__aarch64__)
// aarch64 pt_regs starts with user_pt_regs: regs[31], sp, pc, pstate (34 u64).
static const char *const reg_names[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
	"x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
	"sp", "pc", "pstate"
};
#define REG_PC 32
#elif defined(R2_EBPF_RISCV64)
// riscv64 pt_regs matches user_regs_struct: epc(pc), ra, sp, gp, tp, t0-t2,
// s0-s1, a0-a7, s2-s11, t3-t6 (32 u64).
static const char *const reg_names[] = {
	"pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
	"t3", "t4", "t5", "t6"
};
#define REG_PC 0
#endif
#define REG_COUNT ((int)(sizeof (reg_names) / sizeof (reg_names[0])))
#define REGBUF (REG_COUNT * sizeof (ut64))

static void print_snapshot(RIO *io, ut64 *r) {
	int i;
	for (i = 0; i < REG_COUNT; i++) {
		io->cb_printf ("%-8s 0x%016"PFMT64x"%s", reg_names[i], r[i],
			(i % 3 == 2)? "\n": "  ");
	}
	if (i % 3 != 0) {
		io->cb_printf ("\n");
	}
}

// Emit the snapshot as r2 flag commands (flagspace 'registers').
static void emit_reg_flags(RIO *io, ut64 *r) {
	int i;
	io->cb_printf ("fs registers\n");
	for (i = 0; i < REG_COUNT; i++) {
		io->cb_printf ("f reg.%s 1 0x%"PFMT64x"\n", reg_names[i], r[i]);
	}
	io->cb_printf ("fs *\n");
}
#endif

typedef struct {
	int mem_fd; // /proc/pid/mem
	int pid;
	ut64 off; // current seek position (set via __lseek)
	bool spawned; // we fork+exec'd it, so we own its lifetime
	bool writable; // /proc/pid/mem was opened O_RDWR
	char *spawn_path; // argv[0] of a spawned target (for offset-based probing)
#if HAVE_EBPF
	int map_fd; // BPF_MAP_TYPE_ARRAY holding one pt_regs snapshot
	int prog_fd; // loaded KPROBE program
	int perf_fd; // uprobe perf_event the program is attached to
	char *probe_path; // binary the uprobe is planted in
	ut64 probe_addr; // runtime address requested by the user
#endif
} RIOEbpf;

#define RIOEBPF(x) ((RIOEbpf *)(x)->data)

static bool spawn_preexec(RIOEbpf *e);

// A /proc/pid/mem fd is bound to the mm, so it goes stale after the target
// execve's (relevant for spawned processes). Reopen it against the current mm.
static void reopen_mem(RIOEbpf *e) {
	char mempath[64];
	snprintf (mempath, sizeof (mempath), "/proc/%d/mem", e->pid);
	int fd = r_sandbox_open (mempath, e->writable? O_RDWR: O_RDONLY, 0);
	if (fd >= 0) {
		if (e->mem_fd >= 0) {
			close (e->mem_fd);
		}
		e->mem_fd = fd;
	}
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	RIOEbpf *e = RIOEBPF (desc);
	memset (buf, io->Oxff, len);
	if (e->mem_fd < 0) {
		return -1;
	}
	int r = pread (e->mem_fd, buf, len, (off_t)e->off);
	if (r < 0 && e->spawned) {
		// stale fd after execve: reopen once and retry
		reopen_mem (e);
		r = pread (e->mem_fd, buf, len, (off_t)e->off);
	}
	return r;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int len) {
	RIOEbpf *e = RIOEBPF (desc);
	if (e->mem_fd < 0) {
		return -1;
	}
	int r = pwrite (e->mem_fd, buf, len, (off_t)e->off);
	if (r < 0 && e->spawned) {
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

// Returns true if the bpf() syscall exists on this kernel (not whether we are
// privileged enough to use it -- that is reported later, when a probe is set).
static bool ebpf_available(void) {
	union bpf_attr attr = {0};
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = 4;
	attr.max_entries = 1;
	int fd = bpf_ (BPF_MAP_CREATE, &attr);
	if (fd >= 0) {
		close (fd);
		return true;
	}
	return errno != ENOSYS;
}

static int ebpf_regs_map(void) {
	union bpf_attr attr = {0};
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof (ut32);
	attr.value_size = REGBUF;
	attr.max_entries = 1;
	return bpf_ (BPF_MAP_CREATE, &attr);
}

// Hand-assembled KPROBE program (used for uprobes). On hit it copies the
// pt_regs pointed to by the context into map slot 0 via bpf_probe_read.
static int ebpf_load_snapshot_prog(int map_fd) {
	struct bpf_insn prog[] = {
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
	attr.insn_cnt = sizeof (prog) / sizeof (prog[0]);
	attr.license = (ut64)(size_t)"GPL"; // probe_read is a GPL-only helper
	// Load with no verifier log first: passing log_level>0 with an undersized
	// log_buf makes the kernel fail a valid program with ENOSPC.
	int fd = bpf_ (BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		// genuine failure: retry with a large log buffer for diagnostics
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
	int n = read (fd, buf, sizeof (buf) - 1);
	close (fd);
	return (n > 0)? atoi (buf): -1;
}

// Translate a runtime address in the target into (binary path, file offset),
// which is what the uprobe PMU wants. Reads /proc/pid/maps.
static char *addr_to_file_offset(int pid, ut64 addr, ut64 *foff) {
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/maps", pid);
	char *maps = r_file_slurp (path, NULL);
	if (!maps) {
		return NULL;
	}
	char *ret = NULL;
	RList *lines = r_str_split_list (maps, "\n", 0);
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
		ut64 start = 0, end = 0, off = 0;
		char perms[8] = {0};
		// 0055.. -0055.. r-xp 00001000 fd:01 1234 /path/to/bin
		if (sscanf (line, "%"PFMT64x"-%"PFMT64x" %7s %"PFMT64x, &start, &end, perms, &off) != 4) {
			continue;
		}
		if (addr < start || addr >= end || perms[2] != 'x') {
			continue;
		}
		char *sp = strchr (line, '/');
		if (!sp) {
			continue;
		}
		*foff = addr - start + off;
		ret = strdup (r_str_trim_head_ro (sp));
		break;
	}
	r_list_free (lines);
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
	R_FREE (e->probe_path);
	e->probe_addr = 0;
}

static bool ebpf_probe(RIOEbpf *e, ut64 addr) {
	int ptype = uprobe_pmu_type ();
	if (ptype < 0) {
		R_LOG_ERROR ("Kernel has no uprobe PMU (need CONFIG_UPROBE_EVENTS)");
		return false;
	}
	// Resolve the probe address to (binary, file offset). Prefer /proc/pid/maps
	// so a runtime address works for both attached and already-exec'd spawned
	// targets. Only when the binary is not mapped yet (a spawned target still
	// stopped pre-execve) do we treat the argument as a raw file offset.
	ut64 foff = 0;
	char *bin = addr_to_file_offset (e->pid, addr, &foff);
	if (!bin) {
		if (e->spawn_path && spawn_preexec (e)) {
			bin = strdup (e->spawn_path);
			foff = addr;
		} else {
			R_LOG_ERROR ("Cannot map 0x%"PFMT64x" to an executable file mapping", addr);
			return false;
		}
	}
	if (e->map_fd < 0) {
		e->map_fd = ebpf_regs_map ();
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
	e->probe_path = bin;
	e->probe_addr = addr;
	R_LOG_INFO ("uprobe armed at %s+0x%"PFMT64x" (run the target so it hits 0x%"PFMT64x")",
		bin, foff, addr);
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

// Print the full GP set from an eBPF uprobe snapshot. Returns false if no probe
// has fired yet (pc == 0), so the caller can fall back to /proc/pid/syscall.
static bool ebpf_snapshot_regs(RIO *io, RIOEbpf *e) {
	ut64 r[REG_COUNT] = {0};
	if (!ebpf_read_regs (e, r) || r[REG_PC] == 0) {
		return false;
	}
	print_snapshot (io, r);
	return true;
}
#endif

// Fallback register read that needs no eBPF and no ptrace: /proc/pid/syscall
// ends with the task's stack pointer and program counter (from task_pt_regs)
// whenever the task is not currently on-CPU. Returns false if it is "running".
static bool proc_pc_sp(int pid, ut64 *pc, ut64 *sp) {
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/syscall", pid);
	char *s = r_file_slurp (path, NULL);
	if (!s) {
		return false;
	}
	r_str_trim (s);
	bool ok = false;
	if (!r_str_startswith (s, "running")) {
		RList *toks = r_str_split_list (s, " ", 0);
		int n = r_list_length (toks);
		if (n >= 2) {
			*pc = r_num_get (NULL, (char *)r_list_get_n (toks, n - 1));
			*sp = r_num_get (NULL, (char *)r_list_get_n (toks, n - 2));
			ok = true;
		}
		r_list_free (toks);
	}
	free (s);
	return ok;
}

// Print registers: prefer a full eBPF uprobe snapshot, else fall back to the
// pc/sp exposed by /proc/pid/syscall (works anytime the target is stopped).
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

// A spawned target is stopped *before* execve, so /proc/pid/{mem,maps,syscall}
// still reflect our forked r2 stub until it is resumed. Detect that so :maps
// and :regs can warn instead of silently showing r2's own state.
static bool spawn_preexec(RIOEbpf *e) {
	if (!e->spawned || !e->spawn_path) {
		return false;
	}
	char link[64], buf[512];
	snprintf (link, sizeof (link), "/proc/%d/exe", e->pid);
	ssize_t n = readlink (link, buf, sizeof (buf) - 1);
	if (n <= 0) {
		return false;
	}
	buf[n] = 0;
	// pre-exec: /proc/pid/exe still points at our own r2 binary, not the target
	return strcmp (r_file_basename (buf), r_file_basename (e->spawn_path)) != 0;
}

// Warn and return true when the target is a spawned stub that hasn't exec'd yet,
// so callers can skip showing r2's own (meaningless) maps/regs/state.
static bool preexec_guard(RIOEbpf *e) {
	if (spawn_preexec (e)) {
		R_LOG_WARN ("target has not exec'd yet (pre-exec stub); run ':cont' or ':contstop' first");
		return true;
	}
	return false;
}

// Dump /proc/pid/maps, optionally as r2 flag commands (flagspace 'maps').
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
	RList *lines = r_str_split_list (m, "\n", 0);
	RListIter *it;
	char *line;
	int idx = 0;
	r_list_foreach (lines, it, line) {
		ut64 start = 0, end = 0;
		char perms[8] = {0};
		if (sscanf (line, "%"PFMT64x"-%"PFMT64x" %7s", &start, &end, perms) != 3) {
			continue;
		}
		if (!as_flags) {
			// reformat the range as "0x.. - 0x.." for easy copy-paste
			const char *rest = strchr (line, ' ');
			io->cb_printf ("0x%"PFMT64x" - 0x%"PFMT64x"%s\n", start, end, rest? rest: "");
			continue;
		}
		const char *sp = strchr (line, '/');
		char *name = sp? r_str_newf ("%s", r_file_basename (r_str_trim_head_ro (sp))): strdup ("anon");
		r_name_filter (name, -1);
		io->cb_printf ("f map.%d.%s 0x%"PFMT64x" 0x%"PFMT64x"\n", idx++, name, end - start, start);
		free (name);
	}
	if (as_flags) {
		io->cb_printf ("fs *\n");
	}
	r_list_free (lines);
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

// Poll /proc/pid/stat until the process is in the stopped (T) state, without
// ptrace. Returns false if it dies or never stops.
static bool wait_stopped(int pid) {
	char path[64];
	snprintf (path, sizeof (path), "/proc/%d/stat", pid);
	int i;
	for (i = 0; i < 1000; i++) {
		char *s = r_file_slurp (path, NULL);
		if (!s) {
			return false; // gone
		}
		// "pid (comm) STATE ..." -- comm may hold spaces/parens, skip to last ')'
		char *p = strrchr (s, ')');
		bool stopped = p && p[1] == ' ' && (p[2] == 'T' || p[2] == 't');
		free (s);
		if (stopped) {
			return true;
		}
		r_sys_usleep (1000);
	}
	return false;
}

// Spawn the target ourselves. The child self-stops with SIGSTOP *before* execve
// (no PTRACE_TRACEME, so TracerPid stays 0), letting us open it and arm probes
// while frozen. ':cont' resumes it into execve.
static int ebpf_spawn(const char *cmdline, char **path_out) {
	int argc = 0;
	char **argv = r_str_argv (cmdline, &argc);
	if (!argv || argc < 1) {
		r_str_argv_free (argv);
		return -1;
	}
	int pid = fork ();
	if (pid < 0) {
		r_str_argv_free (argv);
		return -1;
	}
	if (pid == 0) {
		raise (SIGSTOP);
		execv (argv[0], argv);
		_exit (127);
	}
	if (path_out) {
		*path_out = strdup (argv[0]);
	}
	r_str_argv_free (argv);
	if (!wait_stopped (pid)) {
		R_LOG_ERROR ("Spawned pid %d did not stop", pid);
		kill (pid, SIGKILL);
		waitpid (pid, NULL, 0);
		return -1;
	}
	return pid;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (!__plugin_open (io, file, false)) {
		return NULL;
	}
	const char *arg = file + strlen ("ebpf://");
	bool spawned = false;
	char *spawn_path = NULL;
	int pid;
	if (strchr (arg, '/')) {
		// ebpf:///bin/ls -> spawn (stopped pre-exec)
		pid = ebpf_spawn (arg, &spawn_path);
		spawned = true;
	} else {
		pid = atoi (arg);
	}
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
	int perm = R_PERM_R | R_PERM_X | (writable? R_PERM_W: 0);
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
	if (e->mem_fd >= 0) {
		close (e->mem_fd);
	}
	if (e->spawned && e->pid > 0) {
		kill (e->pid, SIGKILL);
		waitpid (e->pid, NULL, 0);
	}
	free (e->spawn_path);
	R_FREE (desc->data);
	return true;
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	RIOEbpf *e = RIOEBPF (desc);
	if (r_str_startswith (cmd, "pid")) {
		// pid stays the first token so scripts can still parse it
		char *exe = r_sys_pidpath (e->pid);
		io->cb_printf ("%d %s%s%s\n", e->pid, e->spawned? "spawned": "attached",
			exe? " ": "", exe? exe: "");
		free (exe);
		return NULL;
	}
	if (r_str_startswith (cmd, "maps")) {
		if (!preexec_guard (e)) {
			emit_maps (io, e, false);
		}
		return NULL;
	}
	if (r_str_startswith (cmd, "r2")) {
		if (!preexec_guard (e)) {
			emit_r2 (io, e);
		}
		return NULL;
	}
	if (r_str_startswith (cmd, "contstop")) {
		// unreliable "step": resume, let it run briefly, then freeze again.
		// optional arg is the run window in milliseconds (0 = as fast as possible)
		const char *arg = r_str_trim_head_ro (cmd + strlen ("contstop"));
		ut64 ms = *arg? r_num_get (NULL, arg): 0;
		kill (e->pid, SIGCONT);
		if (ms > 0) {
			r_sys_usleep (ms * 1000);
		}
		kill (e->pid, SIGSTOP);
		if (!wait_stopped (e->pid)) {
			R_LOG_WARN ("Target did not re-stop (may have exited)");
		}
		reopen_mem (e); // mm may have changed (execve) while it ran
		return NULL;
	}
	if (r_str_startswith (cmd, "cont")) {
		kill (e->pid, SIGCONT);
		return NULL;
	}
	if (r_str_startswith (cmd, "stop")) {
		kill (e->pid, SIGSTOP);
		if (!wait_stopped (e->pid)) {
			R_LOG_WARN ("Target did not stop (may have exited)");
		}
		reopen_mem (e);
		return NULL;
	}
	if (r_str_startswith (cmd, "kill")) {
		kill (e->pid, SIGKILL);
		return NULL;
	}
	if (r_str_startswith (cmd, "regs") || !strcmp (cmd, "r")) {
		if (!preexec_guard (e)) {
			print_regs (io, e);
		}
		return NULL;
	}
#if HAVE_EBPF
	if (r_str_startswith (cmd, "probe-")) {
		ebpf_detach (e);
		return NULL;
	}
	if (r_str_startswith (cmd, "probe")) {
		const char *arg = r_str_trim_head_ro (cmd + strlen ("probe"));
		if (!*arg) {
			R_LOG_ERROR ("Usage: :probe <addr>");
			return NULL;
		}
		ebpf_probe (e, r_num_get (NULL, arg));
		return NULL;
	}
#endif
	if (!*cmd) {
		return NULL; // r2 probes plugins with an empty system command
	}
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
		":kill           SIGKILL the target\n"
		":regs           print registers (eBPF snapshot, else pc/sp from /proc)\n"
		":probe <addr>   arm an eBPF uprobe that snapshots full registers at addr\n"
		":probe-         remove the current uprobe\n"
		"note: memory read/write uses /proc/pid/mem (no ptrace, TracerPid stays 0)\n"
		"note: eBPF traces, it cannot step/pause the process nor rewrite its regs\n");
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
