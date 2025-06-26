/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_userconf.h>
#include <r_drx.h>
#include <r_core.h>
#include <signal.h>
#include <sys/types.h>

#if DEBUGGER

#include "native/drx.c" // x86 specific
#include "r_cons.h"

static bool r_debug_native_continue(RDebug *dbg, int pid, int tid, int sig);
static bool r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
static bool r_debug_native_reg_write(RDebug *dbg, int type, const ut8* buf, int size);
struct r_debug_desc_plugin_t r_debug_desc_plugin_native;
bool linux_generate_corefile(RDebug *dbg, RBuffer *dest);

#include "native/bt.c"

#if R2__UNIX__
# include <errno.h>
# if !defined (__HAIKU__) && !defined (__sun) && !APPLE_SDK_IPHONEOS
#  include <sys/ptrace.h>
# endif
# include <sys/wait.h>
# include <signal.h>
#endif

#if R2__WINDOWS__
//#include <windows.h>
#include "native/windows/windows_debug.h"
// TODO: Move these onto windows.h?
R_API RList *r_w32_dbg_modules(RDebug *); //ugly!
R_API RList *r_w32_dbg_maps(RDebug *);
#define R_DEBUG_REG_T CONTEXT
#ifdef NTSTATUS
#undef NTSTATUS
#endif
#ifndef NTSTATUS
#define NTSTATUS int
#endif

#elif R2__BSD__
#include "native/bsd/bsd_debug.h"
#include "native/procfs.h"

#elif __APPLE__
#include <sys/resource.h>
#include "native/xnu/xnu_debug.h"

#elif __sun

# define R_DEBUG_REG_T gregset_t
# undef DEBUGGER
# define DEBUGGER 0
# warning No debugger support for SunOS yet

#elif __linux__
#include <sys/mman.h>
#include "native/linux/linux_debug.h"
#include "native/procfs.h"
# ifdef __ANDROID__
#  define WAIT_ANY -1
#  ifndef WIFCONTINUED
#   define WIFCONTINUED(s) ((s) == 0xffff)
#  endif
# endif
#if (__x86_64__ || __i386__ || __arm__ || __arm64__) && !defined(__ANDROID__)
#include "native/linux/linux_coredump.h"
#endif
#else // OS

#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // ARCH

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

#endif /* IF DEBUGGER */

/* begin of debugger code */
#if DEBUGGER

#if !R2__WINDOWS__ && !(__linux__ && !defined(WAIT_ON_ALL_CHILDREN)) && !__APPLE__
static int r_debug_handle_signals(RDebug *dbg) {
#if __KFBSD__
	return bsd_handle_signals (dbg);
#else
	R_LOG_WARN ("signal handling is not supported on this platform");
	return 0;
#endif
}
#endif

#if __APPLE__ || __linux__

static char *r_debug_native_reg_profile(RDebug *dbg) {
#if __APPLE__
	return xnu_reg_profile (dbg);
#elif __linux__
	return linux_reg_profile (dbg);
#endif
}
#else

#include "native/reg.c" // x86 specific

#endif
static bool r_debug_native_step(RDebug *dbg) {
#if __APPLE__
	return xnu_step (dbg);
#elif R2__WINDOWS__
	return w32_step (dbg);
#elif R2__BSD__
	int ret = ptrace (PT_STEP, dbg->pid, (caddr_t)1, 0);
	if (ret != 0) {
		r_sys_perror ("native-singlestep");
		return false;
	}
	return true;
#else // linux
	return linux_step (dbg);
#endif
}

static bool r_debug_native_attach(RDebug *dbg, int pid) {
	if (pid < 0) {
		return false;
	}
#if __APPLE__
	return xnu_attach (dbg, pid);
#elif R2__WINDOWS__
	return w32_attach (dbg, pid);
#elif __linux__ || __ANDROID__
	return linux_attach (dbg, pid);
#elif __KFBSD__
	if (ptrace (PT_ATTACH, pid, 0, 0) != -1) {
		r_sys_perror ("ptrace (PT_ATTACH)");
	}
	return true;
#else
	int ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret != -1) {
		R_LOG_INFO ("Trying to attach to %d", pid);
		r_sys_perror ("ptrace (PT_ATTACH)");
	}
	return true;
#endif
}

static bool r_debug_native_detach(RDebug *dbg, int pid) {
#if __APPLE__
	return xnu_detach (dbg, pid);
#elif R2__WINDOWS__
	return w32_detach (dbg, pid);
#elif R2__BSD__
	return ptrace (PT_DETACH, pid, NULL, 0);
#else
	return r_debug_ptrace (dbg, PTRACE_DETACH, pid, NULL, (r_ptrace_data_t)(size_t)0);
#endif
}

#if R2__WINDOWS__ || __linux__
static bool r_debug_native_select(RDebug *dbg, int pid, int tid) {
#if R2__WINDOWS__
	return w32_select (dbg, pid, tid);
#elif __linux__
	return linux_select (dbg, pid, tid);
#else
	return false;
#endif
}
#endif

static bool r_debug_native_continue_syscall(RDebug *dbg, int pid, int num) {
// XXX: num is ignored
#if __linux__
	linux_set_options (dbg, pid);
	return r_debug_ptrace (dbg, PTRACE_SYSCALL, pid, 0, 0);
#elif R2__BSD__
	ut64 pc = r_debug_reg_get (dbg, "PC");
	errno = 0;
	return ptrace (PTRACE_SYSCALL, pid, (void*)(size_t)pc, 0) == 0;
#else
	R_LOG_TODO ("continue syscall not implemented yet");
	return false;
#endif
}

#if !R2__WINDOWS__ && !__APPLE__ && !R2__BSD__
/* Callback to trigger SIGINT signal */
static void interrupt_process(RDebug *dbg) {
	RCore *core = dbg->coreb.core;
	r_debug_kill (dbg, dbg->pid, dbg->tid, SIGINT);
	r_cons_break_pop (core->cons);
}
#endif

static bool r_debug_native_stop(RDebug *dbg) {
#if __linux__
	// Stop all running threads except the thread reported by waitpid
	return linux_stop_threads (dbg, dbg->reason.tid);
#else
	return 0;
#endif
}

static bool r_debug_native_continue(RDebug *dbg, int pid, int tid, int sig) {
#if __APPLE__
	return xnu_continue (dbg, pid, tid, sig);
#elif R2__WINDOWS__
	return w32_continue (dbg, pid, tid, sig);
#elif R2__BSD__
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	ut64 pc = r_debug_reg_get (dbg, "PC");
	return ptrace (PTRACE_CONT, pid, (void*)(size_t)pc, (int)(size_t)data) == 0;
#else
	int ret = -1;
	if (sig == -1) {
		   sig = dbg->reason.signum;
	}
	RCore *core = dbg->coreb.core;
	/* SIGINT handler for attached processes: dbg.consbreak (disabled by default) */
	if (dbg->consbreak) {
		r_cons_break_push (core->cons, (RConsBreak)interrupt_process, dbg);
	}
	if (dbg->continue_all_threads && dbg->n_threads && dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (dbg->threads, it, th) {
			ret = r_debug_ptrace (dbg, PTRACE_CONT, th->pid, 0, 0);
			if (ret) {
				R_LOG_ERROR ("(%d) is running or dead", th->pid);
			}
		}
	} else {
		ret = r_debug_ptrace (dbg, PTRACE_CONT, tid, NULL, (r_ptrace_data_t)(size_t) sig);
		if (ret) {
			r_sys_perror ("PTRACE_CONT");
		}
	}
	return ret >= 0;
#endif
}

static RDebugInfo* r_debug_native_info(RDebug *dbg, const char *arg) {
#if __APPLE__
	return xnu_info (dbg, arg);
#elif R2__WINDOWS__
	return w32_info (dbg, arg);
#elif __linux__
	return linux_info (dbg, arg);
#elif __KFBSD__ || __OpenBSD__ || __NetBSD__
	return bsd_info (dbg, arg);
#else
	return NULL;
#endif
}

#if R2__WINDOWS__
static bool tracelib(RDebug *dbg, const char *mode, PLIB_ITEM item) {
	RCore *core = dbg->coreb.core;
	const char *needle = NULL;
	int tmp = 0;
	if (mode) {
		switch (mode[0]) {
		case 'l': needle = dbg->glob_libs; break;
		case 'u': needle = dbg->glob_unlibs; break;
		}
	}
	r_cons_printf (core->cons, "(%d) %sing library at 0x%p (%s) %s\n", item->pid, mode,
		item->BaseOfDll, item->Path, item->Name);
	r_cons_flush (core->cons);
	if (needle && strlen (needle)) {
		tmp = r_str_glob (item->Name, needle);
	}
	return !mode || !needle || tmp ;
}
#endif

/*
 * Wait for an event and start trying to figure out what to do with it.
 *
 * Returns R_DEBUG_REASON_*
 */
#if R2__WINDOWS__
static RDebugReasonType r_debug_native_wait(RDebug *dbg, int pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
	// Store the original TID to attempt to switch back after handling events that
	// require switching to the event's thread that shouldn't bother the user
	int orig_tid = dbg->tid;
	bool restore_thread = false;
	RW32Dw *wrap = dbg->user;
	RCore *core = dbg->coreb.core;
	RCons *cons = core->cons;

	if (pid == -1) {
		R_LOG_ERROR ("r_debug_native_wait called with pid -1");
		return R_DEBUG_REASON_ERROR;
	}

	reason = w32_dbg_wait (dbg, pid);
	if (reason == R_DEBUG_REASON_NEW_LIB) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->lib) {
			if (tracelib (dbg, "load", r->lib)) {
				reason = R_DEBUG_REASON_TRAP;
			}

			/* Check if autoload PDB is set, and load PDB information if yes */
			RCore *core = dbg->coreb.core;
			bool autoload_pdb = dbg->coreb.cfgGetI (core, "pdb.autoload");
			if (autoload_pdb) {
				PLIB_ITEM lib = r->lib;
#if 0
				dbg->coreb.cmdf (core, "\"o \\\"%s\\\" 0x%p\"", lib->Path, lib->BaseOfDll);
				char *o_res = dbg->coreb.cmdStrF (core, "o~+%s", lib->Name);
				int fd = atoi (o_res);
				free (o_res);
				if (fd) {
					char *pdb_file = dbg->coreb.cmdStr (core, "i~dbg_file");
					if (pdb_file && (r_str_trim (pdb_file), *pdb_file)) {
						if (!r_file_exists (pdb_file + 9)) {
#else
				RBinFileOptions opts = { 0 };
				opts.baseaddr = (uintptr_t)lib->BaseOfDll;
				// RBinFile *bf = r_bin_file_open (core->bin, lib->Path, &opts);
				if (!r_bin_open (core->bin, lib->Path, &opts)) {
					R_LOG_ERROR ("cannot open file");
					return R_DEBUG_REASON_ERROR;
				}
				// file_new (core->bin, lib->Path, 0, 0, bf->fd, NULL, NULL, false);
				RBinFile *bf = r_bin_cur (core->bin);
				if (bf) {
					const RBinInfo *info = r_bin_get_info (core->bin);
					if (info && R_STR_ISNOTEMPTY (info->debug_file_name)) {
						if (!r_file_exists (info->debug_file_name)) {
#endif
							dbg->coreb.cmdf (core, "idpd");
						}
						dbg->coreb.cmdf (core, "idp");
					}
					dbg->coreb.cmdf (core, "o-%d", bf->fd);
				}
			}
			r_debug_info_free (r);
		} else {
			r_cons_flush (core->cons);
			R_LOG_WARN ("Loading unknown library");
		}
		restore_thread = true;
	} else if (reason == R_DEBUG_REASON_EXIT_LIB) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->lib) {
			if (tracelib (dbg, "unload", r->lib)) {
				reason = R_DEBUG_REASON_TRAP;
			}
			r_debug_info_free (r);
		} else {
			r_cons_printf (core->cons, "Unloading unknown library.\n");
			r_cons_flush (core->cons);
		}
		restore_thread = true;
	} else if (reason == R_DEBUG_REASON_NEW_TID) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			r_cons_printf (cons, "(%d) Created thread %d (start @ %p) (teb @ %p)\n", item->pid, item->tid, item->lpStartAddress, item->lpThreadLocalBase);
			r_cons_flush (cons);

			r_debug_info_free (r);
		}
		restore_thread = true;
	} else if (reason == R_DEBUG_REASON_EXIT_TID) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			r_cons_printf (cons, "(%d) Finished thread %d Exit code %lu\n", (ut32)item->pid, (ut32)item->tid, item->dwExitCode);
			r_cons_flush (cons);

			r_debug_info_free (r);
		}
		if (dbg->tid != orig_tid) {
			restore_thread = true;
		}
	} else if (reason == R_DEBUG_REASON_DEAD) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			r_cons_printf (cons, "(%d) Finished process with exit code %lu\n", dbg->main_pid, item->dwExitCode);
			r_cons_flush (cons);
			r_debug_info_free (r);
		}
		dbg->pid = -1;
		dbg->tid = -1;
	} else if (reason == R_DEBUG_REASON_USERSUSP && dbg->tid != orig_tid) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->thread) {
			PTHREAD_ITEM item = r->thread;
			r_cons_printf (cons, "(%d) Created DebugBreak thread %d (start @ %p)\n", item->pid, item->tid, item->lpStartAddress);
			r_cons_flush (cons);

			r_debug_info_free (r);
		}
		// DebugProcessBreak creates a new thread that will trigger a breakpoint. We record the
		// tid here to ignore it once the breakpoint is hit.
		wrap->break_tid = dbg->tid;
		restore_thread = true;
	} else if (reason == R_DEBUG_REASON_BREAKPOINT && dbg->tid == wrap->break_tid) {
		wrap->break_tid = -2;
		reason = R_DEBUG_REASON_NONE;
		restore_thread = true;
	}

	if (restore_thread) {
		// Attempt to return to the original thread after handling the event
		w32_select (dbg, dbg->pid, orig_tid);
		// dbg->tid = w32_select (dbg, dbg->pid, orig_tid);
		if (dbg->tid == -1) {
			dbg->pid = -1;
			reason = R_DEBUG_REASON_DEAD;
		} else {
			r_strf_var (pidcmd, 32, "pid %d", dbg->tid);
			r_io_system (dbg->iob.io, pidcmd);
			if (dbg->tid != orig_tid) {
				reason = R_DEBUG_REASON_UNKNOWN;
			}
		}
	}

	dbg->reason.tid = pid;
	dbg->reason.type = reason;
	return reason;
}
// FIXME: Should WAIT_ON_ALL_CHILDREN be a compilation flag instead of runtime debug config?
#elif __linux__ && !defined(WAIT_ON_ALL_CHILDREN) // R2__WINDOWS__
static RDebugReasonType r_debug_native_wait(RDebug *dbg, int pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		R_LOG_ERROR ("r_debug_native_wait called with pid -1");
		return R_DEBUG_REASON_ERROR;
	}

	reason = linux_dbg_wait (dbg, dbg->tid);
	dbg->reason.type = reason;
	return reason;
}
#else // if R2__WINDOWS__ & elif __linux__ && !defined (WAIT_ON_ALL_CHILDREN)
static RDebugReasonType r_debug_native_wait(RDebug *dbg, int pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		R_LOG_ERROR ("r_debug_native_wait called with pid -1");
		return R_DEBUG_REASON_ERROR;
	}

#if __APPLE__
	if (pid < 0) {
		return R_DEBUG_REASON_ERROR;
	}
	RCore *core = dbg->coreb.core;
	r_cons_break_push (core->cons, NULL, NULL);
	do {
		reason = xnu_wait (dbg, pid);
		if (reason == R_DEBUG_REASON_MACH_RCV_INTERRUPTED) {
			if (r_cons_is_breaked (core->cons)) {
				// Perhaps check the inferior is still alive,
				// otherwise xnu_stop will fail.
				reason = xnu_stop (dbg, pid)
					? R_DEBUG_REASON_USERSUSP
					: R_DEBUG_REASON_UNKNOWN;
			} else {
				// Weird; we'll retry the wait.
				continue;
			}
		}
		break;
	} while (true);
	r_cons_break_pop (core->cons);
#else
	int status = -1;
	// XXX: this is blocking, ^C will be ignored
#ifdef WAIT_ON_ALL_CHILDREN
	int ret = waitpid (-1, &status, WAITPID_FLAGS);
#else
	int ret = waitpid (-1, &status, 0);
	if (ret != -1) {
		reason = R_DEBUG_REASON_TRAP;
	}
#endif // WAIT_ON_ALL_CHILDREN
	if (ret == -1) {
		r_sys_perror ("waitpid");
		return R_DEBUG_REASON_ERROR;
	}
#ifdef WAIT_ON_ALL_CHILDREN
	if (ret != pid) {
		reason = R_DEBUG_REASON_NEW_PID;
		r_debug_select (dbg, ret, -1);
	}
#endif // WAIT_ON_ALL_CHILDREN
	// TODO: switch status and handle reasons here
	// FIXME: Remove linux handling from this function?
#if __linux__ && defined(PT_GETEVENTMSG)
	reason = linux_ptrace_event (dbg, pid, status, true);
#endif // __linux__

	/* propagate errors */
	if (reason == R_DEBUG_REASON_ERROR) {
		return reason;
	}

	/* we don't know what to do yet, let's try harder to figure it out. */
#if __FreeBSD__
	if (reason == R_DEBUG_REASON_TRAP) {
#else
	if (reason == R_DEBUG_REASON_UNKNOWN) {
#endif
		if (WIFEXITED (status)) {
			R_LOG_INFO ("child exited with status %d", WEXITSTATUS (status));
			reason = R_DEBUG_REASON_DEAD;
		} else if (WIFSIGNALED (status)) {
			R_LOG_INFO ("child received signal %d", WTERMSIG (status));
			reason = R_DEBUG_REASON_SIGNAL;
		} else if (WIFSTOPPED (status)) {
			if (WSTOPSIG (status) != SIGTRAP &&
				WSTOPSIG (status) != SIGSTOP) {
				R_LOG_INFO ("Child stopped with signal %d", WSTOPSIG (status));
			}

			/* the ptrace documentation says GETSIGINFO is only necessary for
			 * differentiating the various stops.
			 *
			 * this might modify dbg->reason.signum
			 */
#if R2__BSD__
			reason = R_DEBUG_REASON_BREAKPOINT;
#else
			if (r_debug_handle_signals (dbg) != 0) {
				return R_DEBUG_REASON_ERROR;
			}
			reason = dbg->reason.type;
#endif
#ifdef WIFCONTINUED
		} else if (WIFCONTINUED (status)) {
			R_LOG_INFO ("child continued");
			reason = R_DEBUG_REASON_NONE;
#endif
		} else if (status == 1) {
			/* XXX(jjd): does this actually happen? */
			R_LOG_ERROR ("EEK DEAD DEBUGEE!");
			reason = R_DEBUG_REASON_DEAD;
		} else if (status == 0) {
			/* XXX(jjd): does this actually happen? */
			R_LOG_ERROR ("STATUS=0?!?!?!?");
			reason = R_DEBUG_REASON_DEAD;
		} else {
			if (ret != pid) {
				reason = R_DEBUG_REASON_NEW_PID;
			} else {
				/* ugh. still don't know :-/ */
				R_LOG_ERROR ("CRAP. returning from wait without knowing why");
			}
		}
	}

	/* if we still don't know what to do, we have a problem... */
	if (reason == R_DEBUG_REASON_UNKNOWN) {
		R_LOG_INFO ("no idea what happened here");
		reason = R_DEBUG_REASON_ERROR;
	}
#endif // __APPLE__
	dbg->reason.tid = pid;
	dbg->reason.type = reason;
	return reason;
}
#endif // R2__WINDOWS__

#undef MAXPID
#define MAXPID 99999

static RList *r_debug_native_tids(RDebug *dbg, int pid) {
	printf ("TODO: Threads: \n");
	// T
	return NULL;
}

static RList *r_debug_native_pids(RDebug *dbg, int pid) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
#if __APPLE__
	if (pid) {
		RDebugPid *p = xnu_get_pid (pid);
		if (p) {
			r_list_append (list, p);
		}
	} else {
		int i;
		for (i = 1; i < MAXPID; i++) {
			RDebugPid *p = xnu_get_pid (i);
			if (p) {
				r_list_append (list, p);
			}
		}
	}
#elif R2__WINDOWS__
	return w32_pid_list (dbg, pid, list);
#elif __linux__
	return linux_pid_list (pid, list);
#else /* rest is BSD */
	return bsd_pid_list (dbg, pid, list);
#endif
	return list;
}

static RList *r_debug_native_threads(RDebug *dbg, int pid) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
#if __APPLE__
	return xnu_thread_list (dbg, pid, list);
#elif R2__WINDOWS__
	return w32_thread_list (dbg, pid, list);
#elif __linux__
	return linux_thread_list (dbg, pid, list);
#else
	return bsd_thread_list (dbg, pid, list);
#endif
}

#if __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__ || __DragonFly__

//Function to read register from Linux, BSD, Android systems
static int bsd_reg_read(RDebug *dbg, int type, ut8* buf, int size) {
	int showfpu = false;
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __KFBSD__ && (__i386__ || __x86_64__)
		{
			struct dbreg dbr;
			if (ptrace (PT_GETDBREGS, pid, (caddr_t)&dbr, sizeof (dbr)) != 0) {
				return false;
			}
		}
#endif
		return true;
		break;
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_VEC64: // MMX
	   ret = ptrace (PT_GETFPREGS, pid, (caddr_t)buf, sizeof (struct fpreg));
	   break;
	case R_REG_TYPE_VEC128: // XMM
	case R_REG_TYPE_VEC256: // YMM
	case R_REG_TYPE_VEC512: // ZMM
#if __KFBSD__ && (__i386__ || __x86_64__)
		struct ptrace_xstate_info info;
		ret = ptrace (PT_GETXSTATE_INFO, pid, (caddr_t)&info, sizeof (info));
		if (info.xsave_len != 0) {
			ret = ptrace (PT_GETXSTATE, pid, (caddr_t)buf, info.xsave_len);
		}
#endif
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
		R_DEBUG_REG_T regs;
		memset (&regs, 0, sizeof (regs));
		memset (buf, 0, size);
		#if __NetBSD__ || __OpenBSD__
			ret = ptrace (PTRACE_GETREGS, pid, (caddr_t)&regs, sizeof (regs));
		#elif __KFBSD__
			ret = ptrace (PT_GETREGS, pid, (caddr_t)&regs, 0);
		#else
			#warning not implemented for this platform
			ret = 1;
		#endif
		// if perror here says 'no such process' and the
		// process exists still.. is because there's a
		// missing call to 'wait'. and the process is not
		// yet available to accept more ptrace queries.
		if (ret != 0) {
			return false;
		}
		if (sizeof (regs) < size) {
			size = sizeof (regs);
		}
		memcpy (buf, &regs, size);
		return sizeof (regs);
		}
		break;
	}
	return true;
}
#endif // if __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__



// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static bool r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
#if __APPLE__
	return xnu_reg_read (dbg, type, buf, size);
#elif R2__WINDOWS__
	return w32_reg_read (dbg, type, buf, size);
#elif __linux__
	return linux_reg_read (dbg, type, buf, size);
#elif __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__ || __DragonFly__
	return bsd_reg_read (dbg, type, buf, size);
#else
	#warning dbg-native not supported for this platform
	return false;
#endif
}

static bool r_debug_native_reg_write(RDebug *dbg, int type, const ut8* buf, int size) {
	// XXX use switch or so
	if (type == R_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
#if __APPLE__
		return xnu_reg_write (dbg, type, buf, size);
#elif R2__WINDOWS__
		return w32_reg_write (dbg, type, buf, size);
#elif __linux__
		return linux_reg_write (dbg, type, buf, size);
#else
		return bsd_reg_write (dbg, type, buf, size);
#endif
#else // i386/x86-64
		return false;
#endif
	} else if (type == R_REG_TYPE_GPR) {
#if __APPLE__
		return xnu_reg_write (dbg, type, buf, size);
#elif R2__WINDOWS__
		return w32_reg_write (dbg, type, buf, size);
#elif __linux__
		return linux_reg_write (dbg, type, buf, size);
#elif __sun
		int ret = ptrace (PTRACE_SETREGS, dbg->pid,
			(void*)(size_t)buf, sizeof (R_DEBUG_REG_T));
		if (sizeof (R_DEBUG_REG_T) < size) {
			size = sizeof (R_DEBUG_REG_T);
		}
		return ret == 0;
#else
		return bsd_reg_write (dbg, type, buf, size);
#endif
	} else if (type == R_REG_TYPE_FPU) {
#if __linux__
		return linux_reg_write (dbg, type, buf, size);
#elif __APPLE__
		return false;
#elif R2__WINDOWS__
		return false;
#else
		return bsd_reg_write (dbg, type, buf, size);
#endif
	} //else R_LOG_TODO ("reg_write_non-gpr (%d)", type);
	return false;
}

#if __linux__
static int io_perms_to_prot(int io_perms) {
	int prot_perms = PROT_NONE;

	if (io_perms & R_PERM_R) {
		prot_perms |= PROT_READ;
	}
	if (io_perms & R_PERM_W) {
		prot_perms |= PROT_WRITE;
	}
	if (io_perms & R_PERM_X) {
		prot_perms |= PROT_EXEC;
	}
	return prot_perms;
}

#if __linux__
static int thp_mode(void) {
	const char *thp = "/sys/kernel/mm/transparent_hugepage/enabled";
	int ret = 0;
	char *val = r_file_slurp (thp, NULL);
	if (val) {
		if (strstr (val, "[madvise]")) {
			ret = 1;
		} else if (strstr (val, "[always]")) {
			ret = 2;
		}
		free (val);
	}
	return ret;
}
#endif

static bool linux_map_thp(RDebug *dbg, ut64 addr, int size) {
#if !defined(__ANDROID__) && defined(MADV_HUGEPAGE)
	RBuffer *buf = NULL;
	char code[1024];
	bool ret = true;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	// In architectures where radare is supported, arm and x86, it is 2MB
	const size_t thpsize = 1<<21;

	if (size % thpsize) {
		R_LOG_ERROR ("size not a power of huge pages size");
		return false;
	}
#if __linux__
	// In always mode, is more into mmap syscall level
	// even though the address might not have the 'hg'
	// vmflags
	if (thp_mode () != 1) {
		R_LOG_ERROR ("transparent huge page mode is not in madvise mode");
		return false;
	}
#endif
	int num = r_syscall_get_num (dbg->anal->syscall, "madvise");

	snprintf (code, sizeof (code),
		"sc_madvise@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_madvise(0x%08" PFMT64x ",%d, %d);break;\n"
		"}\n",
		num, addr, size, MADV_HUGEPAGE);
	r_egg_reset (dbg->egg);
	r_egg_setup (dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	r_egg_load (dbg->egg, code, 0);
	if (!r_egg_compile (dbg->egg)) {
		R_LOG_ERROR ("Cannot compile");
		goto err_linux_map_thp;
	}
	if (!r_egg_assemble_asm (dbg->egg, asm_list)) {
		R_LOG_ERROR ("r_egg_assemble: invalid assembly");
		goto err_linux_map_thp;
	}
	buf = r_egg_get_bin (dbg->egg);
	if (buf) {
		ut64 tmpsz, retval;
		r_reg_arena_push (dbg->reg);
		const ut8 *tmp = r_buf_data (buf, &tmpsz);
		if (!r_debug_execute (dbg, tmp, tmpsz, &retval, true, false)) {
			R_LOG_ERROR ("Failed to execute code");
		}
		ret = (retval == 0);
		r_reg_arena_pop (dbg->reg);
	}
err_linux_map_thp:
	return ret;
#else
	return false;
#endif
}

static RDebugMap* linux_map_alloc(RDebug *dbg, ut64 addr, int size, bool thp) {
	RBuffer *buf = NULL;
	RDebugMap* map = NULL;
	char code[1024], *sc_name;
	int num;
	/* force to usage of x86.as, not yet working x86.nz */
	char *asm_list[] = {
			"x86", "x86.as",
			"x64", "x86.as",
			NULL};
#if 0
NOTE: Since kernel 2.4,  that  system  call  has  been  superseded  by
mmap2(2 and  nowadays  the  glibc  mmap()  wrapper  function invokes
mmap2(2)). If arch is x86_32 then usage mmap2() */
#endif
	if (!strcmp (dbg->arch, "x86") && dbg->bits == 4) {
		sc_name = "mmap2";
	} else {
		sc_name = "mmap";
	}
	num = r_syscall_get_num (dbg->anal->syscall, sc_name);
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
	snprintf (code, sizeof (code),
		"sc_mmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_mmap(0x%08"PFMT64x",%d,%d,%d,%d,%d);break;\n"
		"}\n",
		num, addr, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	r_egg_reset (dbg->egg);
	r_egg_setup (dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	r_egg_load (dbg->egg, code, 0);
	if (!r_egg_compile (dbg->egg)) {
		R_LOG_ERROR ("Cannot compile");
		goto err_linux_map_alloc;
	}
	if (!r_egg_assemble_asm (dbg->egg, asm_list)) {
		R_LOG_ERROR ("r_egg_assemble: invalid assembly");
		goto err_linux_map_alloc;
	}
	buf = r_egg_get_bin (dbg->egg);
	if (buf) {
		ut64 map_addr;

		r_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = r_buf_data (buf, &tmpsz);
		if (!r_debug_execute (dbg, tmp, tmpsz, &map_addr, true, false)) {
			R_LOG_ERROR ("Failed to execute code");
			goto err_linux_map_alloc;
		}
		r_reg_arena_pop (dbg->reg);
		if (map_addr < UT64_MAX) {
			if (thp) {
				if (!linux_map_thp (dbg, map_addr, size)) {
					R_LOG_WARN ("map promotion to huge page failed");
				}
			}
			r_debug_map_sync (dbg);
			map = r_debug_map_get (dbg, map_addr);
		}
	}
err_linux_map_alloc:
	return map;
}

static bool linux_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	RBuffer *buf = NULL;
	char code[1024];
	ut64 ret = 0;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	int num = r_syscall_get_num (dbg->anal->syscall, "munmap");

	snprintf (code, sizeof (code),
		"sc_munmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_munmap(0x%08" PFMT64x ",%d);break;\n"
		"}\n",
		num, addr, size);
	r_egg_reset (dbg->egg);
	r_egg_setup (dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	r_egg_load (dbg->egg, code, 0);
	if (!r_egg_compile (dbg->egg)) {
		R_LOG_ERROR ("Cannot compile");
		goto err_linux_map_dealloc;
	}
	if (!r_egg_assemble_asm (dbg->egg, asm_list)) {
		R_LOG_ERROR ("r_egg_assemble: invalid assembly");
		goto err_linux_map_dealloc;
	}
	buf = r_egg_get_bin (dbg->egg);
	if (buf) {
		r_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = r_buf_data (buf, &tmpsz);
		if (!r_debug_execute (dbg, tmp, tmpsz, &ret, true, false)) {
			R_LOG_ERROR ("Failed to execute code");
		}
		r_reg_arena_pop (dbg->reg);
	}
err_linux_map_dealloc:
	return ret == 0;
}
#endif

static RDebugMap* r_debug_native_map_alloc(RDebug *dbg, ut64 addr, int size, bool thp) {
#if __APPLE__
	(void)thp;
	return xnu_map_alloc (dbg, addr, size);
#elif R2__WINDOWS__
	(void)thp;
	return w32_map_alloc (dbg, addr, size);
#elif __linux__
	return linux_map_alloc (dbg, addr, size, thp);
#else
	// malloc not implemented for this platform
	return NULL;
#endif
}

static bool r_debug_native_map_dealloc(RDebug *dbg, ut64 addr, int size) {
#if __APPLE__
	return xnu_map_dealloc (dbg, addr, size);
#elif R2__WINDOWS__
	return w32_map_dealloc (dbg, addr, size);
#elif __linux__
	return linux_map_dealloc (dbg, addr, size);
#else
	// mdealloc not implemented for this platform
	return false;
#endif
}

#if !R2__WINDOWS__ && !__APPLE__
static void _map_free(RDebugMap *map) {
	if (map) {
		free (map->name);
		free (map->file);
		free (map);
	}
}
#endif

static RList *r_debug_native_map_get(RDebug *dbg) {
	RList *list = NULL;
#if __KFBSD__
	int ign;
	char unkstr[128];
#endif
#if __APPLE__
	list = xnu_dbg_maps (dbg, 0);
#elif R2__WINDOWS__
	list = r_w32_dbg_maps (dbg);
#else
#if __sun
	char path[1024];
	/* TODO: On solaris parse /proc/%d/map */
	snprintf (path, sizeof (path) - 1, "pmap %d >&2", ps.tid);
	system (path);
#else
	RDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024], name[1024];
	char region[100], region2[100], perms[5];
	FILE *fd;
	if (dbg->pid == -1) {
		// R_LOG_ERROR ("r_debug_native_map_get: No selected pid (-1)");
		return NULL;
	}
	/* prepend 0x prefix */
	region[0] = region2[0] = '0';
	region[1] = region2[1] = 'x';

#if __OpenBSD__
	/* OpenBSD has no procfs, so no idea trying. */
	return bsd_native_sysctl_map (dbg);
#endif

#if __KFBSD__
	list = bsd_native_sysctl_map (dbg);
	if (list) {
		return list;
	}
	snprintf (path, sizeof (path), "/proc/%d/map", dbg->pid);
#else
	snprintf (path, sizeof (path), "/proc/%d/maps", dbg->pid);
#endif
	fd = r_sandbox_fopen (path, "r");
	if (!fd) {
		char *errstr = r_str_newf ("Cannot open '%s'", path);
		r_sys_perror (errstr);
		free (errstr);
		return NULL;
	}

	list = r_list_new ();
	if (!list) {
		fclose (fd);
		return NULL;
	}
	list->free = (RListFree)_map_free;
	while (!feof (fd)) {
		size_t line_len;
		bool map_is_shared = false;
		ut64 map_start, map_end;

		if (!fgets (line, sizeof (line), fd)) {
			break;
		}
		/* kill the newline if we got one */
		line_len = strlen (line);
		if (line[line_len - 1] == '\n') {
			line[line_len - 1] = '\0';
			line_len--;
		}
		/* maps files should not have empty lines */
		if (line_len == 0) {
			break;
		}
#if __KFBSD__
		// 0x8070000 0x8072000 2 0 0xc1fde948 rw- 1 0 0x2180 COW NC vnode /usr/bin/gcc
		if (r_str_scanf (line, "%.s %.s %*d %*d %*s %.s %*d %*d",
			sizeof (region)-2, &region[2], sizeof (region2)-2, &region2[2], sizeof (perms), perms) != 3) {
			R_LOG_ERROR ("%s: Unable to parse \"%s\"", __func__, path);
			r_list_free (list);
			return NULL;
		}

		/* snag the file name */
		pos_c = strchr (line, '/');
		if (pos_c) {
			strncpy (name, pos_c, sizeof (name) - 1);
		} else {
			name[0] = '\0';
		}
#else
		ut64 offset = 0;
		// 7fc8124c4000-7fc81278d000 r--p 00000000 fc:00 17043921 /usr/lib/locale/locale-archive
		i = r_str_scanf (line, "%.s %.s %Lx %*s %*s %.[^\n]",
			sizeof (region) - 2, &region[2],
			sizeof (perms), perms,
			&offset,
			sizeof (name), name);
		if (i == 3) {
			name[0] = '\0';
		} else if (i != 4) {
			R_LOG_ERROR ("Unable to parse \"%s\" %d vs 4", path, i);
			R_LOG_ERROR ("Line: %s", line);
			r_list_free (list);
			return NULL;
		}

		/* split the region in two */
		pos_c = strchr (&region[2], '-');
		if (!pos_c) { // should this be an error?
			continue;
		}
		strncpy (&region2[2], pos_c + 1, sizeof (region2) - 2 - 1);
#endif // __KFBSD__
		if (!*name) {
			snprintf (name, sizeof (name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; i < 5 && perms[i]; i++) {
			switch (perms[i]) {
			case 'r': perm |= R_PERM_R; break;
			case 'w': perm |= R_PERM_W; break;
			case 'x': perm |= R_PERM_X; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}

		map_start = r_num_get (NULL, region);
		map_end = r_num_get (NULL, region2);
		if (map_start == map_end || map_end == 0) {
			R_LOG_ERROR ("ignoring invalid map size: %s - %s", region, region2);
			continue;
		}
		map = r_debug_map_new (name, map_start, map_end, perm, 0);
		if (!map) {
			break;
		}
#if __linux__
		map->offset = offset;
		map->shared = map_is_shared;
#endif
		map->file = strdup (name);
#if 0
		// TODO: this breaks 'dcu main' on linux, guess it's about bad use of map.file vs map.name
		if (!strcmp (map->file, map->name)) {
			const char *last_slash = r_str_lchr (map->file, '/');
			if (last_slash) {
				char *new_name = strdup (last_slash + 1);
				free (map->name);
				map->name = new_name;
			}
		}
#endif
		r_list_append (list, map);
	}
	fclose (fd);
#endif // __sun
#endif // __APPLE__
	return list;
}

static RList *r_debug_native_modules_get(RDebug *dbg) {
	char *lastname = NULL;
	RDebugMap *map;
	RListIter *iter, *iter2;
	RList *list, *last;
	bool must_delete;
#if __APPLE__
	list = xnu_dbg_maps (dbg, 1);
	if (list && !r_list_empty (list)) {
		return list;
	}
#elif  R2__WINDOWS__
	list = r_w32_dbg_modules (dbg);
	if (list && !r_list_empty (list)) {
		return list;
	}
#endif
	if (!(list = r_debug_native_map_get (dbg))) {
		return NULL;
	}
	if (!(last = r_list_newf ((RListFree)r_debug_map_free))) {
		r_list_free (list);
		return NULL;
	}
	r_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			if (!map->name) {
				map->name = strdup ("");
			}
			file = map->file = strdup (map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp (lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			r_list_delete (list, iter);
		} else {
			r_list_append (last, map);
			free (lastname);
			lastname = strdup (file);
		}
	}
	list->free = NULL;
	free (lastname);
	r_list_free (list);
	return last;
}

static bool r_debug_native_kill(RDebug *dbg, int pid, int tid, int sig) {
	bool ret = false;
	if (pid < 1) {
		pid = dbg->pid;
	}
#if R2__WINDOWS__
	ret = w32_kill (dbg, pid, tid, sig);
#else
#if 0
	if (thread) {
// XXX this is linux>2.5 specific..ugly
		if (dbg->tid>0 && (ret = tgkill (dbg->pid, dbg->tid, sig))) {
			if (ret != -1)
				ret = true;
		}
	} else {
#endif
	if (sig == SIGKILL && dbg->threads) {
		r_list_free (dbg->threads);
		dbg->threads = NULL;
	}
	if ((r_sandbox_kill (pid, sig) != -1)) {
		ret = true;
	}
	if (errno == 1) {
		ret = -true; // EPERM
	}
#if 0
//	}
#endif
#endif
	return ret;
}

static bool r_debug_native_init(RDebug *dbg) {
	dbg->current->plugin->desc = r_debug_desc_plugin_native;
#if R2__WINDOWS__
	r_w32_init ();
	if (!dbg->user && dbg->iob.io->dbgwrap) {
		dbg->user = (RW32Dw *)dbg->iob.io->dbgwrap;
	}
#endif
	return true;
}

#if __i386__ || __x86_64__
static void sync_drx_regs(RDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		R_LOG_ERROR ("drx: Unsupported number of registers for get_debug_regs");
		return;
	}

	// sync drx regs
#define R dbg->reg
	regs[0] = r_reg_getv (R, "dr0");
	regs[1] = r_reg_getv (R, "dr1");
	regs[2] = r_reg_getv (R, "dr2");
	regs[3] = r_reg_getv (R, "dr3");
/*
	RESERVED
	regs[4] = r_reg_getv (R, "dr4");
	regs[5] = r_reg_getv (R, "dr5");
*/
	regs[6] = r_reg_getv (R, "dr6");
	regs[7] = r_reg_getv (R, "dr7");
}
#endif

#if __i386__ || __x86_64__
static void set_drx_regs(RDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		R_LOG_ERROR ("drx: Unsupported number of registers for get_debug_regs");
		return;
	}

#define R dbg->reg
 	r_reg_setv (R, "dr0", regs[0]);
	r_reg_setv (R, "dr1", regs[1]);
	r_reg_setv (R, "dr2", regs[2]);
	r_reg_setv (R, "dr3", regs[3]);
	r_reg_setv (R, "dr6", regs[6]);
	r_reg_setv (R, "dr7", regs[7]);
}
#endif

static bool r_debug_native_drx(RDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
#if __i386__ || __x86_64__
	int retval = false;
#if NUM_DRX_REGISTERS > 0
	drxt regs[NUM_DRX_REGISTERS] = {0};
	sync_drx_regs (dbg, regs, NUM_DRX_REGISTERS);
#else
	drxt regs[1] = {0};
#endif
	switch (api_type) {
	case DRX_API_LIST:
		drx_list (regs);
		retval = false;
		break;
	case DRX_API_GET_BP:
		/* get the index of the breakpoint at addr */
		retval = drx_get_at (regs, addr);
		break;
	case DRX_API_REMOVE_BP:
		/* remove hardware breakpoint */
		drx_set (regs, n, addr, -1, 0, 0);
		retval = true;
		break;
	case DRX_API_SET_BP:
		/* set hardware breakpoint */
		drx_set (regs, n, addr, sz, rwx, g);
		retval = true;
		break;
	default:
		/* this should not happen, someone misused the API */
		R_LOG_ERROR ("drx: Unsupported api type in r_debug_native_drx");
		retval = false;
	}

	set_drx_regs (dbg, regs, NUM_DRX_REGISTERS);

	return retval;
#else
	R_LOG_ERROR ("drx: registers only available on x86. Use dbH for native hardware breakpoints and watchpoints");
#endif
	return false;
}


#if __linux__

#if __arm__ || __arm64__ || __aarch64__
#include <sys/prctl.h>
#include <sys/uio.h>

#define NT_ARM_VFP	0x400		/* ARM VFP/NEON registers */
#define NT_ARM_TLS	0x401		/* ARM TLS register */
#define NT_ARM_HW_BREAK	0x402		/* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH	0x403		/* ARM hardware watchpoint registers */
#define NT_ARM_SYSTEM_CALL	0x404	/* ARM system call number */

#ifndef PTRACE_GETHBPREGS
#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30
#endif

#if __arm__

static bool ll_arm32_hwbp_set(pid_t pid, ut64 addr, int size, int wp, int type) {
	const unsigned byte_mask = (1 << size) - 1;
	//const unsigned type = 2; // Write.
	const unsigned enable = 1;
	const unsigned control = byte_mask << 5 | type << 3 | enable;
	(void)ptrace (PTRACE_SETHBPREGS, pid, -1, (void*)(size_t)addr);
	return ptrace (PTRACE_SETHBPREGS, pid, -2, &control) != -1;
}

static bool arm32_hwbp_add(RDebug *dbg, RBreakpoint* bp, RBreakpointItem *b) {
	return ll_arm32_hwbp_set (dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

static bool arm32_hwbp_del(RDebug *dbg, RBreakpoint *bp, RBreakpointItem *b) {
	return false; // TODO: hwbp.del not yetimplemented
}
#endif // PTRACE_GETHWBPREGS
#endif // __arm

#if (__arm64__ || __aarch64__) && defined(PTRACE_GETREGSET)
// type = 2 = write
//static volatile uint8_t var[96] __attribute__((__aligned__(32)));

static bool ll_arm64_hwbp_set(pid_t pid, ut64 _addr, int size, int wp, ut32 type) {
	const volatile uint8_t *addr = (void*)(size_t)_addr; //&var[32 + wp];
	const unsigned int offset = (uintptr_t)addr % 8;
	const ut32 byte_mask = ((1 << size) - 1) << offset;
	const ut32 enable = 1;
	const ut32 control = byte_mask << 5 | type << 3 | enable;

	struct user_hwdebug_state dreg_state = {0};
	struct iovec iov = {0};
	iov.iov_base = &dreg_state;
	iov.iov_len = sizeof (dreg_state);

	if (ptrace (PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
		// error reading regs
	}
	memcpy (&dreg_state, iov.iov_base, sizeof (dreg_state));
	// wp is not honored here i think... we can't have more than one wp for now..
	dreg_state.dbg_regs[0].addr = (uintptr_t)(addr - offset);
	dreg_state.dbg_regs[0].ctrl = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = r_offsetof (struct user_hwdebug_state, dbg_regs) +
				sizeof (dreg_state.dbg_regs[0]);
	if (ptrace (PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
		return true;
	}

	if (errno == EIO) {
		R_LOG_ERROR ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s",
			strerror (errno));
	}

	R_LOG_ERROR ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s", strerror (errno));
	return false;
}

static bool ll_arm64_hwbp_del(pid_t pid, ut64 _addr, int size, int wp, ut32 type) {
	// const volatile uint8_t *addr = &var[32 + wp];
	// TODO: support multiple watchpoints and find
	struct user_hwdebug_state dreg_state = {0};
	struct iovec iov = {0};
	iov.iov_base = &dreg_state;
	// only delete 1 bp for now
	iov.iov_len = r_offsetof (struct user_hwdebug_state, dbg_regs) +
				sizeof (dreg_state.dbg_regs[0]);
	if (ptrace (PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
		return true;
	}
	if (errno == EIO) {
		R_LOG_ERROR ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s",
			strerror (errno));
	}

	R_LOG_ERROR ("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s", strerror (errno));
	return false;
}

static bool arm64_hwbp_add(RDebug *dbg, RBreakpoint* bp, RBreakpointItem *b) {
	return ll_arm64_hwbp_set (dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

static bool arm64_hwbp_del(RDebug *dbg, RBreakpoint *bp, RBreakpointItem *b) {
	return ll_arm64_hwbp_del (dbg->pid, b->addr, b->size, 0, 1 | 2 | 4);
}

#endif //  __arm64__
#endif // __linux__

/*
 * set or unset breakpoints...
 *
 * we only handle the case for hardware breakpoints here. otherwise,
 * we let the caller handle the work.
 */
// TODO should return bool
static int r_debug_native_bp(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	if (b && b->hw) {
#if __i386__ || __x86_64__
		RDebug *dbg = bp->user;
		return set
			? drx_add (dbg, bp, b)
			: drx_del (dbg, bp, b);
#elif (__arm64__ || __arm64e__ || __aarch64__) && __linux__
		RDebug *dbg = bp->user;
		return set
			? arm64_hwbp_add (dbg, bp, b)
			: arm64_hwbp_del (dbg, bp, b);
#elif __arm__ && __linux__
		RDebug *dbg = bp->user;
		return set
			? arm32_hwbp_add (dbg, bp, b)
			: arm32_hwbp_del (dbg, bp, b);
#elif __riscv && __linux__
		// no hw bps afaik
		return false;
#else
#ifdef _MSC_VER
#pragma message ( "r_debug_native_bp not implemented for this platform" )
#else
#warning r_debug_native_bp not implemented for this platform
#endif
#endif
	}
	return false;
}

#if __APPLE__

#if TARGET_OS_IPHONE || __POWERPC__
	// nothing to do
#else
static int getMaxFiles(void) {
	struct rlimit limit;
	if (getrlimit (RLIMIT_NOFILE, &limit) != 0) {
		return 1024;
	}
	return limit.rlim_cur;
}
#endif

static RList *xnu_desc_list(int pid) {
#if TARGET_OS_IPHONE || __POWERPC__
	return NULL;
#else
#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
	RDebugDesc *desc;
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	struct vnode_fdinfowithpath vi;
	int i, nb, type = 0;
	int maxfd = getMaxFiles();

	for (i = 0; i < maxfd; i++) {
		nb = proc_pidfdinfo (pid, i, PROC_PIDFDVNODEPATHINFO, &vi, sizeof (vi));
		if (nb < 1) {
			continue;
		}
		if (nb < sizeof (vi)) {
			r_sys_perror ("too few bytes");
			break;
		}
		//printf ("FD %d RWX %x ", i, vi.pfi.fi_openflags);
		//printf ("PATH %s\n", vi.pvip.vip_path);
		desc = r_debug_desc_new (i,
				vi.pvip.vip_path,
				xwr2rwx(vi.pfi.fi_openflags),
				type, 0);
		r_list_append (ret, desc);
	}
	return ret;
#endif
}
#endif

static RList *r_debug_desc_native_list(int pid) {
#if __APPLE__
	return xnu_desc_list (pid);
#elif R2__WINDOWS__
	return w32_desc_list (pid);
#elif __KFBSD__
	return bsd_desc_list (pid);
#elif __linux__
	return linux_desc_list (pid);
#else
#warning list filedescriptors not supported for this platform
	return NULL;
#endif
}

static bool r_debug_native_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
#if R2__WINDOWS__
	return w32_map_protect (dbg, addr, size, perms);
#elif __APPLE__
	return xnu_map_protect (dbg, addr, size, perms);
#elif __linux__
	RBuffer *buf = NULL;
	char code[1024];
	const int num = r_syscall_get_num (dbg->anal->syscall, "mprotect");
	snprintf (code, sizeof (code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%p,%d,%d);\n"
		":int3\n"
		"}\n", num, (void*)(size_t)addr, size, io_perms_to_prot (perms));

	r_egg_reset (dbg->egg);
	r_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	r_egg_load (dbg->egg, code, 0);
	if (!r_egg_compile (dbg->egg)) {
		R_LOG_ERROR ("Cannot compile");
		return false;
	}
	if (!r_egg_assemble (dbg->egg)) {
		R_LOG_ERROR ("r_egg_assemble: invalid assembly");
		return false;
	}
	buf = r_egg_get_bin (dbg->egg);
	if (buf) {
		r_reg_arena_push (dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = r_buf_data (buf, &tmpsz);
		if (!r_debug_execute (dbg, tmp, tmpsz, NULL, true, false)) {
			R_LOG_ERROR ("Failed to execute code");
		}
		r_reg_arena_pop (dbg->reg);
		return true;
	}
#endif
	return false;
}

static int r_debug_desc_native_open(const char *path) {
	return 0;
}

static bool r_debug_gcore(RDebug *dbg, RBuffer *dest) {
#if __APPLE__
	return xnu_generate_corefile (dbg, dest);
#elif __linux__ && (__x86_64__ || __i386__ || __arm__ || __arm64__)
#  if __ANDROID__
	return false;
#  else
	return linux_generate_corefile (dbg, dest);
#  endif
#else
	return false;
#endif
}

struct r_debug_desc_plugin_t r_debug_desc_plugin_native = {
	.open = r_debug_desc_native_open,
	.list = r_debug_desc_native_list,
};

RDebugPlugin r_debug_plugin_native = {
	.meta = {
		.name = "native",
		.author = "pancake",
		.license = "LGPL-3.0-only",
		.desc = "native debug plugin",
	},
#if __i386__
	.bits = R_SYS_BITS_PACK (32),
	.arch = "x86",
	.canstep = true,
#elif __s390x__ || __s390__
	.bits = R_SYS_BITS_PACK (64),
	.arch = "s390",
	.canstep = true,
#elif __riscv || __riscv__ || __riscv64__
	.bits = R_SYS_BITS_PACK (64),
	.arch = "riscv",
	.canstep = false,
#elif __x86_64__
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.arch = "x86",
	.canstep = true, // XXX it's 1 on some platforms...
#elif __aarch64__ || __arm64__ || __arm64e__
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.arch = "arm",
#if __APPLE__
	.canstep = true,
#else
	.canstep = false,
#endif
#elif __arm__
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.arch = "arm",
	.canstep = false,
#elif __mips__
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.arch = "mips",
	.canstep = false,
#elif __loongarch
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.arch = "loongarch",
	.canstep = false,
#elif __powerpc__
# if __powerpc64__
	.bits = R_SYS_BITS_PACK2 (32, 64),
# else
	.bits = R_SYS_BITS_PACK (32),
#endif
	.arch = "ppc",
	.canstep = true,
#else
	.bits = 0,
	.arch = 0,
	.canstep = false,
#ifdef _MSC_VER
#pragma message("Unsupported architecture")
#else
#warning Unsupported architecture
#endif
#endif
	.init_debugger = &r_debug_native_init,
	.step = &r_debug_native_step,
	.cont = &r_debug_native_continue,
	.stop = &r_debug_native_stop,
	.contsc = &r_debug_native_continue_syscall,
	.attach = &r_debug_native_attach,
	.detach = &r_debug_native_detach,
// TODO: add native select for other platforms?
#if R2__WINDOWS__ || __linux__
	.select = &r_debug_native_select,
#endif
	.pids = &r_debug_native_pids,
	.tids = &r_debug_native_tids,
	.threads = &r_debug_native_threads,
	.wait = &r_debug_native_wait,
	.kill = &r_debug_native_kill,
	.frames = &r_debug_native_frames, // rename to backtrace ?
	.reg_profile = r_debug_native_reg_profile,
	.reg_read = r_debug_native_reg_read,
	.info = r_debug_native_info,
	.reg_write = (void *)&r_debug_native_reg_write,
	.map_alloc = r_debug_native_map_alloc,
	.map_dealloc = r_debug_native_map_dealloc,
	.map_get = r_debug_native_map_get,
	.modules_get = r_debug_native_modules_get,
	.map_protect = r_debug_native_map_protect,
	.breakpoint = r_debug_native_bp,
	.drx = r_debug_native_drx,
	.gcore = r_debug_gcore,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_native,
	.version = R2_VERSION
};
#endif // R2_PLUGIN_INCORE

//#endif
#else // DEBUGGER
RDebugPlugin r_debug_plugin_native = {
	NULL // .name = "native",
};

#endif // DEBUGGER
