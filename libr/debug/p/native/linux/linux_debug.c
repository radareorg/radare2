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

#ifdef __GLIBC__
#define HAVE_YMM 1
#else
#define HAVE_YMM 0
#endif

char *linux_reg_profile (RDebug *dbg) {
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
			if (dbg->glob_libs || dbg->glob_unlibs) {
				ut64 pc_addr = r_debug_reg_get (dbg, "PC");
				RBreakpointItem *b = r_bp_get_at (dbg->bp, pc_addr - dbg->bpsize);
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
		if (dbg->trace_clone) {
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
		if (!dbg->trace_forks) {
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
		//TODO: Check other processes exit if dbg->trace_forks is on
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
	if (dbg->trace_forks) {
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	if (dbg->trace_aftersyscall) {
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
		if (dbg->continue_all_threads) {
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
	if (!rdi) {
		return NULL;
	}

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
	if (!pid_info) {
		return NULL;
	}
	char *ptr = strstr (info, "State:");
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

#define PRINT_FPU(cons, fpregs) \
	r_cons_printf (cons, "cwd = 0x%04x  ; control   ", (fpregs).cwd);\
	r_cons_printf (cons, "swd = 0x%04x  ; status\n", (fpregs).swd);\
	r_cons_printf (cons, "ftw = 0x%04x              ", (fpregs).ftw);\
	r_cons_printf (cons, "fop = 0x%04x\n", (fpregs).fop);\
	r_cons_printf (cons, "rip = 0x%016"PFMT64x"  ", (ut64)(fpregs).rip);\
	r_cons_printf (cons, "rdp = 0x%016"PFMT64x"\n", (ut64)(fpregs).rdp);\
	r_cons_printf (cons, "mxcsr = 0x%08x        ", (fpregs).mxcsr);\
	r_cons_printf (cons, "mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)\

#define PRINT_FPU_NOXMM(cons, fpregs) \
	r_cons_printf (cons, "cwd = 0x%04lx  ; control   ", (fpregs).cwd);\
	r_cons_printf (cons, "swd = 0x%04lx  ; status\n", (fpregs).swd);\
	r_cons_printf (cons, "twd = 0x%04lx              ", (fpregs).twd);\
	r_cons_printf (cons, "fip = 0x%04lx          \n", (fpregs).fip);\
	r_cons_printf (cons, "fcs = 0x%04lx              ", (fpregs).fcs);\
	r_cons_printf (cons, "foo = 0x%04lx          \n", (fpregs).foo);\
	r_cons_printf (cons, "fos = 0x%04lx              ", (fpregs).fos)

static void print_fpu(RCons *cons, void *f) {
	if (!f) {
		R_LOG_WARN ("getfpregs not implemented");
		return;
	}
#if __x86_64__
	int i,j;
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
#if __ANDROID__
	PRINT_FPU (cons, fpregs);
	for (i = 0;i < 8; i++) {
		ut64 *b = (ut64 *)&fpregs.st_space[i*4];
		ut32 *c = (ut32*)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		r_cons_printf (cons, "st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (%08x) | "\
			"%0.3f (%08x) \n", i,
			(double)*((double*)&fpregs.st_space[i*4]), *b, (float) f[0],
			c[0], (float) f[1], c[1]);
	}
#else
	r_cons_printf (cons, "---- x86-64 ----\n");
	PRINT_FPU (cons, fpregs);
	r_cons_printf (cons, "size = 0x%08x\n", (ut32)sizeof (fpregs));
	for (i = 0; i < 16; i++) {
		ut32 *a = (ut32 *)&fpregs.xmm_space;
		a = a + (i * 4);
		r_cons_printf (cons, "xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
					   (int)a[2], (int)a[3] );
		if (i < 8) {
			ut64 *st_u64 = (ut64*)&fpregs.st_space[i * 4];
			ut8 *st_u8 = (ut8 *)&fpregs.st_space[i * 4];
			long double *st_ld = (long double *)&fpregs.st_space[i * 4];
			r_cons_printf (cons, "mm%d = 0x%016" PFMT64x " | st%d = ", i, *st_u64, i);
			// print as hex TBYTE - always little endian
			for (j = 9; j >= 0; j--) {
				r_cons_printf (cons, "%02x", st_u8[j]);
			}
			// Using %Lf and %Le even though we do not show the extra precision to avoid another cast
			// %f with (double)*st_ld would also work
#if R2_NO_LONG_DOUBLE
			r_cons_printf (cons, " %e %f\n", (double)(*st_ld), (double)(*st_ld));
#else
			r_cons_printf (cons, " %Le %Lf\n", *st_ld, *st_ld);
#endif
		} else {
			r_cons_printf (cons, "\n");
		}
	}
#endif // __ANDROID__
#elif __i386__
	int i;
#if __ANDROID__
	struct user_fpxregs_struct fpxregs = *(struct user_fpxregs_struct*)f;
	r_cons_printf (cons, "---- x86-32 ----\n");
	r_cons_printf (cons, "cwd = 0x%04x  ; control   ", fpxregs.cwd);
	r_cons_printf (cons, "swd = 0x%04x  ; status\n", fpxregs.swd);
	r_cons_printf (cons, "twd = 0x%04x ", fpxregs.twd);
	r_cons_printf (cons, "fop = 0x%04x\n", fpxregs.fop);
	r_cons_printf (cons, "fip = 0x%08x\n", (ut32)fpxregs.fip);
	r_cons_printf (cons, "fcs = 0x%08x\n", (ut32)fpxregs.fcs);
	r_cons_printf (cons, "foo = 0x%08x\n", (ut32)fpxregs.foo);
	r_cons_printf (cons, "fos = 0x%08x\n", (ut32)fpxregs.fos);
	r_cons_printf (cons, "mxcsr = 0x%08x\n", (ut32)fpxregs.mxcsr);
	for (i = 0; i < 8; i++) {
		ut32 *a = (ut32*)(&fpxregs.xmm_space);
		ut64 *b = (ut64 *)(&fpxregs.st_space[i * 4]);
		ut32 *c = (ut32*)&fpxregs.st_space;
		float *f = (float *)&fpxregs.st_space;
		a = a + (i * 4);
		c = c + (i * 4);
		f = f + (i * 4);
		r_cons_printf (cons, "xmm%d = %08x %08x %08x %08x   ", i, (int)a[0],
			(int)a[1], (int)a[2], (int)a[3] );
		r_cons_printf (cons, "st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x) | "\
			"%0.3f (0x%08x)\n", i,
			(double)*((double*)(&fpxregs.st_space[i*4])), b[0],
			f[0], c[0], f[1], c[1]);
	}
#else
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	r_cons_printf (cons, "---- x86-32-noxmm ----\n");
	PRINT_FPU_NOXMM (cons, fpregs);
	for (i = 0; i < 8; i++) {
		ut64 *b = (ut64 *)(&fpregs.st_space[i*4]);
		double *d = (double*)b;
		ut32 *c = (ut32*)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		r_cons_printf (cons, "st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x) | "\
			"%0.3f (0x%08x)\n", i, d[0], b[0], f[0], c[0], f[1], c[1]);
	}
#endif
#elif __arm64__ || __aarch64__
	{
		// ARM64/AArch64 FPSIMD state is typically 528 bytes:
		// - 32x 128-bit vector registers (v0-v31), also viewed as d0-d31/s0-s31
		// - FP status and control registers (FPSR, FPCR)
		// The code below interprets the first 512 bytes as v0-v31 in various views.
		ut8 *fpu_regs = (ut8 *)f;
		int i;

		// Print vector registers (128-bit)
		r_cons_printf (cons, "Vector registers (v0-v31):\n");
		for (i = 0; i < 32; i++) {
			ut32 *reg = (ut32 *)(fpu_regs + i * 16);
			r_cons_printf (cons, "v%d = 0x%08x %08x %08x %08x\n", i,
				(int)reg[0], (int)reg[1], (int)reg[2], (int)reg[3]);
		}

		// Print FP registers as doubles (64-bit)
		r_cons_printf (cons, "\nDouble precision FP registers (d0-d31):\n");
		for (i = 0; i < 32; i++) {
			double *dreg = (double *)(fpu_regs + i * 16);
			r_cons_printf (cons, "d%d = %g (0x%016"PFMT64x")\n", i,
				*dreg, *(ut64 *)dreg);
		}

		// Print FP registers as floats (32-bit)
		r_cons_printf (cons, "\nSingle precision FP registers (s0-s31):\n");
		for (i = 0; i < 32; i++) {
			float *freg = (float *)(fpu_regs + i * 16);
			r_cons_printf (cons, "s%d = %g (0x%08x)\n", i,
				*freg, *(ut32 *)freg);
		}
	}
#elif __arm__
	{
		// ARM32 VFP/NEON registers
		ut8 *fpu_regs = (ut8 *)f;
		int i;

		r_cons_printf (cons, "VFP/NEON registers:\n");
		for (i = 0; i < 32; i++) {
			double *dreg = (double *)(fpu_regs + i * 8);
			r_cons_printf (cons, "d%d = %g (0x%016"PFMT64x")\n", i,
				*dreg, *(ut64 *)dreg);
		}

		r_cons_printf (cons, "\nSingle precision registers (s0-s31):\n");
		for (i = 0; i < 32; i++) {
			/* On ARM32, s-registers are views into the same
			 * physical register file as the d-registers:
			 *   d0 holds s0 (low 32) and s1 (high 32)
			 *   d1 holds s2 (low 32) and s3 (high 32), etc.
			 */
			ut64 *dregs = (ut64 *)fpu_regs;
			int d_index = i / 2;
			ut64 dval = dregs[d_index];
			ut32 sval;
			union {
				ut32 u;
				float f;
			} uval;

#if R_SYS_ENDIAN
			/* Little-endian: low 32 bits are the even s-regs */
			if (i & 1) {
				sval = (ut32)(dval >> 32);
			} else {
				sval = (ut32)(dval & 0xffffffffU);
			}
#else
			/* Big-endian: high 32 bits are the even s-regs */
			if (i & 1) {
				sval = (ut32)(dval & 0xffffffffU);
			} else {
				sval = (ut32)(dval >> 32);
			}
#endif
			uval.u = sval;
			r_cons_printf (cons, "s%d = %g (0x%08x)\n", i,
				uval.f, sval);
		}
	}
#elif __riscv || __riscv__ || __riscv64__
	{
		r_cons_printf (cons, "---- RISC-V ----\n");
		// RISC-V FPU registers: 32x 64-bit double precision registers
		// The layout follows the Linux kernel's fpregs_struct for RV64
		ut8 *fpu_regs = (ut8 *)f;
		int i;

		for (i = 0; i < 32; i++) {
			double *freg = (double *)(fpu_regs + i * 8);
			r_cons_printf (cons, "f%d = %g (0x%016"PFMT64x")\n", i,
				*freg, *(ut64 *)freg);
		}

		r_cons_printf (cons, "\nSingle precision registers (f0-f31 as float):\n");
		for (i = 0; i < 32; i++) {
			float *freg = (float *)(fpu_regs + i * 8);
			r_cons_printf (cons, "f%d = %g (0x%08x)\n", i,
				*freg, *(ut32 *)freg);
		}
	}
#elif __mips__
	{
		r_cons_printf (cons, "---- MIPS ----\n");
		// MIPS FPU registers: 32x 64-bit double precision registers
		ut8 *fpu_regs = (ut8 *)f;
		int i;

		for (i = 0; i < 32; i++) {
			double *freg = (double *)(fpu_regs + i * 8);
			r_cons_printf (cons, "$f%d = %g (0x%016"PFMT64x")\n", i,
				*freg, *(ut64 *)freg);
		}

		r_cons_printf (cons, "\nSingle precision registers ($f0-$f31 as float):\n");
		for (i = 0; i < 32; i++) {
			float *freg = (float *)(fpu_regs + i * 4);
			r_cons_printf (cons, "$f%d = %g (0x%08x)\n", i,
				*freg, *(ut32 *)freg);
		}
	}
#elif __POWERPC__
	{
		r_cons_printf (cons, "---- PowerPC ----\n");
		// PowerPC FPU registers: 32x 64-bit double precision registers
		ut8 *fpu_regs = (ut8 *)f;
		int i;

		for (i = 0; i < 32; i++) {
			double *freg = (double *)(fpu_regs + i * 8);
			r_cons_printf (cons, "f%d = %g (0x%016"PFMT64x")\n", i,
				*freg, *(ut64 *)freg);
		}

		r_cons_printf (cons, "\nSingle precision registers (f0-f31 as float):\n");
		for (i = 0; i < 32; i++) {
#if R_SYS_ENDIAN == R_SYS_ENDIAN_BIG
			float *freg = (float *)(fpu_regs + i * 8 + 4);
#else
			float *freg = (float *)(fpu_regs + i * 8);
#endif
			r_cons_printf (cons, "f%d = %g (0x%08x)\n", i,
				*freg, *(ut32 *)freg);
		}
	}
#elif __s390x__ || __s390__
	{
		r_cons_printf (cons, "---- s390x ----\n");
		// s390x FPU registers: 16x 64-bit double precision registers
		ut8 *fpu_regs = (ut8 *)f;
		int i;

		for (i = 0; i < 16; i++) {
			double *freg = (double *)(fpu_regs + i * 8);
			r_cons_printf (cons, "f%d = %g (0x%016"PFMT64x")\n", i,
				*freg, *(ut64 *)freg);
		}

		r_cons_printf (cons, "\nSingle precision registers (f0-f15 as float):\n");
		for (i = 0; i < 16; i++) {
			float *freg = (float *)(fpu_regs + i * 4);
			r_cons_printf (cons, "f%d = %g (0x%08x)\n", i,
				*freg, *(ut32 *)freg);
		}
	}
#else
#warning print_fpu not implemented for this platform
#endif
}

bool linux_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	bool showfpu = false;
	RCore *core = dbg->coreb.core;
	RCons *cons = core->cons;
	int pid = dbg->tid;
	if (pid == -1) {
		if (dbg->pid == -1) {
			R_LOG_ERROR ("Invalid pid %d", pid);
			return false;
		}
		pid = dbg->pid;
	}
	int ret = 0;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
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
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_VEC64: // MMX
	case R_REG_TYPE_VEC128: // XMM
		{
#if __x86_64__ || __i386__
		struct user_fpregs_struct fpregs;
		if (type == R_REG_TYPE_FPU) {
#if __x86_64__
			ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (ret != 0) {
				r_sys_perror ("PTRACE_GETFPREGS");
				return false;
			}
			if (showfpu) {
				print_fpu (cons, (void *)&fpregs);
			}
			size = R_MIN (sizeof (fpregs), size);
			memcpy (buf, &fpregs, size);
			return size;
#elif __i386__
#if !__ANDROID__
			struct user_fpxregs_struct fpxregs;
			ret = r_debug_ptrace (dbg, PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret == 0) {
				if (showfpu) {
					print_fpu (cons, (void *)&fpxregs);
				}
				size = R_MIN (sizeof (fpxregs), size);
				memcpy (buf, &fpxregs, size);
				return size;
			} else {
				ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) {
					print_fpu (cons, (void *)&fpregs);
				}
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
			if (showfpu) {
				print_fpu (cons, (void *)&fpregs);
			}
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
#elif (__arm64__ || __aarch64__) && defined(PTRACE_GETREGSET)
		// ARM64 FPU register reading using ptrace GETREGSET
		struct iovec iov;
		ut8 fpu_regs[512]; // ARM64 FPU register space (32 * 16 bytes for v0-v31)
		memset (fpu_regs, 0, sizeof (fpu_regs));
		iov.iov_base = fpu_regs;
		iov.iov_len = sizeof (fpu_regs);

		ret = r_debug_ptrace (dbg, PTRACE_GETREGSET, pid, (void*)(size_t)NT_PRFPREG, &iov);
		if (ret != 0) {
			r_sys_perror ("PTRACE_GETREGSET NT_PRFPREG");
			return false;
		}

		if (showfpu) {
			print_fpu (cons, (void *)fpu_regs);
		}

		size = R_MIN (iov.iov_len, size);
		memcpy (buf, fpu_regs, size);
		return size;
#else
		if (showfpu) {
			print_fpu (cons, NULL);
		}
	#warning getfpregs not implemented for this platform
#endif
		}
		break;
	case R_REG_TYPE_VEC512: // ZMM
		R_LOG_DEBUG ("zmm registers not supported yet");
		break;
	case R_REG_TYPE_VEC256: // YMM
		{
#if HAVE_YMM && __x86_64__ && defined(PTRACE_GETREGSET)
		ut32 ymm_space[128];	// full ymm registers
		struct _xstate xstate;
		struct iovec iov = {};
		iov.iov_base = &xstate;
		iov.iov_len = sizeof (struct _xstate);
		ret = r_debug_ptrace (dbg, PTRACE_GETREGSET, pid, (void*)NT_X86_XSTATE, &iov);
		if (errno == ENODEV) {
			// ignore ENODEV, it just means this CPU or kernel doesn't support XSTATE
			ret = 0;
		} else if (ret != 0) {
			if (dbg->verbose) {
				// WSL1 doesnt support retrieving YMM registers, so this call just fails, no need to be noisy
				r_sys_perror ("PTRACE_GETREGSET");
			}
			return false;
		}
		// stitch together xstate.fpstate._xmm and xstate.ymmh assuming LE
		int ri,rj;
		for (ri = 0; ri < 16; ri++)	{
			for (rj = 0; rj < 4; rj++)	{
#ifdef __ANDROID__
				ymm_space[ri*8+rj] = ((struct _libc_fpstate*) &xstate.fpstate)->_xmm[ri].element[rj];
#else
				ymm_space[ri*8+rj] = xstate.fpstate._xmm[ri].element[rj];
#endif
			}
			for (rj = 0; rj < 4; rj++)	{
				ymm_space[ri * 8 + (rj + 4)] = xstate.ymmh.ymmh_space[ri * 4 + rj];
			}
		}
		size = R_MIN (sizeof (ymm_space), size);
		memcpy (buf, &ymm_space, size);
		return size;
#endif
		return false;
		}
		break;
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
#elif (__arm64__ || __aarch64__) && defined(PTRACE_SETREGSET)
		// ARM64 FPU/VEC register writing using ptrace SETREGSET
		struct iovec iov;
		iov.iov_base = (void*)buf;
		iov.iov_len = size;

		int ret = r_debug_ptrace (dbg, PTRACE_SETREGSET, pid, (void*)(size_t)NT_PRFPREG, &iov);
		if (ret != 0) {
			r_sys_perror ("PTRACE_SETREGSET NT_PRFPREG");
			return false;
		}
		return true;
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
