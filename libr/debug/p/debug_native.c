/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include "native/drx.c" // x86 specific
#include "r_cons.h"

#if DEBUGGER

static int r_debug_native_continue (RDebug *dbg, int pid, int tid, int sig);
static int r_debug_native_reg_read (RDebug *dbg, int type, ut8 *buf, int size);
static int r_debug_native_reg_write (RDebug *dbg, int type, const ut8* buf, int size);

#include "native/bt.c"

#if __UNIX__ || __CYGWIN__
# include <errno.h>
# if !defined (__HAIKU__) && !defined (__CYGWIN__)
#  include <sys/ptrace.h>
# endif
# include <sys/wait.h>
# include <signal.h>
#endif

#if __WINDOWS__
#include <windows.h>
#define R_DEBUG_REG_T CONTEXT
#include "native/w32.c"
#ifdef NTSTATUS
#undef NTSTATUS
#endif
#ifndef NTSTATUS
#define NTSTATUS int
#endif

#elif __BSD__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#define R_DEBUG_REG_T struct reg
#if __KFBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

#elif __APPLE__
#include <sys/resource.h>
#include "native/xnu/xnu_debug.h"

#elif __sun

# define R_DEBUG_REG_T gregset_t
# undef DEBUGGER
# define DEBUGGER 0
# warning No debugger support for SunOS yet

#elif __linux__
#include "native/linux/linux_debug.h"
#else // OS

#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // ARCH

#endif /* IF DEBUGGER */

/* begin of debugger code */
#if DEBUGGER

#if !__APPLE__
static int r_debug_handle_signals (RDebug *dbg) {
#if __linux__
	return linux_handle_signals (dbg);
#else
	return -1;
#endif
}
#endif

//this is temporal
#if __APPLE__ || __linux__

static const char *r_debug_native_reg_profile (RDebug *dbg) {
#if __APPLE__
	return xnu_reg_profile (dbg);
#elif __linux__
	return linux_reg_profile (dbg);
#endif
}
#else

#include "native/reg.c" // x86 specific

#endif

static int r_debug_native_step (RDebug *dbg) {
#if __WINDOWS__ && !__CYGWIN__
	/* set TRAP flag */
	CONTEXT regs __attribute__ ((aligned (16)));
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR,
				(ut8 *)&regs, sizeof (regs));
	regs.EFlags |= 0x100;
	r_debug_native_reg_write (dbg, R_REG_TYPE_GPR,
				(ut8 *)&regs, sizeof (regs));
	r_debug_native_continue (dbg, dbg->pid,
				dbg->tid, dbg->reason.signum);
	r_debug_handle_signals (dbg);
	return true;
#elif __APPLE__
	return xnu_step (dbg);
#elif __BSD__
	int ret = ptrace (PT_STEP, dbg->pid, (caddr_t)1, 0);
	if (ret != 0) {
		perror ("native-singlestep");
		return false;
	}
	return true;
#elif __CYGWIN__
	#warning "r_debug_native_step not supported on this platform"
	return false;
#else // linux
	return linux_step (dbg);
#endif
}

// return thread id
static int r_debug_native_attach (RDebug *dbg, int pid) {
#if 0
	if (!dbg || pid == dbg->pid)
		return dbg->tid;
#endif
#if __linux__
	return linux_attach (dbg, pid);
#elif __WINDOWS__ && !__CYGWIN__
	int ret;
	HANDLE process = w32_open_process (PROCESS_ALL_ACCESS, FALSE, pid);
	if (process != (HANDLE)NULL && DebugActiveProcess (pid)) {
		ret = w32_first_thread (pid);
	} else {
		ret = -1;
	}
	ret = w32_first_thread (pid);
	CloseHandle (process);
	return ret;
#elif __CYGWIN__
	#warning "r_debug_native_attach not supported on this platform"
	return -1;
#elif __APPLE__
	return xnu_attach (dbg, pid);
#elif __KFBSD__
	if (ptrace (PT_ATTACH, pid, 0, 0) != -1) perror ("ptrace (PT_ATTACH)");
	return pid;
#else
	int ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret != -1) {
		perror ("ptrace (PT_ATTACH)");
	}
	return pid;
#endif
}

static int r_debug_native_detach (RDebug *dbg, int pid) {
#if __WINDOWS__ && !__CYGWIN__
	return w32_detach (pid)? 0 : -1;
#elif __CYGWIN__
	#warning "r_debug_native_detach not supported on this platform"
	return -1;
#elif __APPLE__
	return xnu_detach (dbg, pid);
#elif __BSD__
	return ptrace (PT_DETACH, pid, NULL, 0);
#else
	return ptrace (PTRACE_DETACH, pid, NULL, NULL);
#endif
}

static int r_debug_native_continue_syscall (RDebug *dbg, int pid, int num) {
// XXX: num is ignored
#if __linux__
	return ptrace (PTRACE_SYSCALL, pid, 0, 0);
#elif __BSD__
	ut64 pc = r_debug_reg_get (dbg, "PC");
	return ptrace (PTRACE_SYSCALL, pid, (void*)(size_t)pc, 0);
#else
	eprintf ("TODO: continue syscall not implemented yet\n");
	return -1;
#endif
}

/* TODO: specify thread? */
/* TODO: must return true/false */
static int r_debug_native_continue (RDebug *dbg, int pid, int tid, int sig) {
#if __WINDOWS__ && !__CYGWIN__
	if (ContinueDebugEvent (pid, tid, DBG_CONTINUE) == 0) {
		print_lasterr ((char *)__FUNCTION__, "ContinueDebugEvent");
		eprintf ("debug_contp: error\n");
		return false;
	}
	return tid;
#elif __APPLE__
	bool ret;
	ret = xnu_continue (dbg, pid, tid, sig);
	if (!ret)
		return -1;
	return tid;
#elif __BSD__
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	ut64 pc = r_debug_reg_get (dbg, "PC");
	return ptrace (PTRACE_CONT, pid, (void*)(size_t)pc, (int)(size_t)data) == 0;
#elif __CYGWIN__
	#warning "r_debug_native_continue not supported on this platform"
	return -1;
#else
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
//eprintf ("SIG %d\n", dbg->reason.signum);
	return ptrace (PTRACE_CONT, pid, NULL, data) == 0;
#endif
}
static RDebugInfo* r_debug_native_info (RDebug *dbg, const char *arg) {
#if __APPLE__
	return xnu_info (dbg, arg);
#elif __linux__
	return linux_info (dbg, arg);
#elif __WINDOWS__
	return w32_info (dbg, arg);
#else
	return NULL;
#endif
}

#if __WINDOWS__ && !__CYGWIN__
static bool tracelib(RDebug *dbg, const char *mode, PLIB_ITEM item) {
	const char *needle = NULL;
	if (mode) {
		switch (mode[0]) {
		case 'l': needle = dbg->glob_libs; break;
		case 'u': needle = dbg->glob_unlibs; break;
		}
	}
	eprintf ("(%d) %sing library at %p (%s) %s\n", item->pid, mode,
		item->BaseOfDll, item->Path, item->Name);
	return !mode || !needle || r_str_glob (item->Name, needle);
}
#endif

static int r_debug_native_wait (RDebug *dbg, int pid) {
	int status = -1;
#if __WINDOWS__ && !__CYGWIN__
	int mode = 0;
	status = w32_dbg_wait (dbg, pid);
	if (status == R_DEBUG_REASON_NEW_LIB) {
		mode = 'l';
	} else if (status == R_DEBUG_REASON_EXIT_LIB) {
		mode = 'u';
	} else {
		mode = 0;
	}
	if (mode) {
		RDebugInfo *r = r_debug_native_info (dbg, "");
		if (r && r->lib) {
			if (tracelib (dbg, mode=='l'? "load":"unload", r->lib))
				status=R_DEBUG_REASON_TRAP;
		} else {
			eprintf ("%soading unknown library.\n", mode?"L":"Unl");
		}
		r_debug_info_free (r);
	}
#else
	if (pid == -1) {
		status = R_DEBUG_REASON_UNKNOWN;
	} else {
#if __APPLE__
		// eprintf ("No waitpid here :D\n");
		status = xnu_wait (dbg, pid);
#else
		// XXX: this is blocking, ^C will be ignored
		int ret = waitpid (pid, &status, 0);
		if (ret == -1) {
			status = R_DEBUG_REASON_ERROR;
		} else {
			//printf ("status=%d (return=%d)\n", status, ret);
			// TODO: switch status and handle reasons here
			r_debug_handle_signals (dbg);

			if (WIFSTOPPED (status)) {
				dbg->reason.signum = WSTOPSIG (status);
				status = R_DEBUG_REASON_SIGNAL;
			} else if (status == 0 || ret == -1) {
				status = R_DEBUG_REASON_DEAD;
			} else {
				if (ret != pid)
					status = R_DEBUG_REASON_NEW_PID;
				else status = R_DEBUG_REASON_UNKNOWN;
			}
		}
#endif
	}
#endif
	dbg->reason.tid = pid;
	dbg->reason.type = status;
	return status;
}

#undef MAXPID
#define MAXPID 99999

static RList *r_debug_native_tids (int pid) {
	printf ("TODO: Threads: \n");
	// T
	return NULL;
}

static RList *r_debug_native_pids (int pid) {
	RList *list = r_list_new ();
#if __WINDOWS__ && !__CYGWIN__
	return w32_pids (pid, list);
#elif __APPLE__

	if (pid) {
		RDebugPid *p = xnu_get_pid (pid);
		if (p) r_list_append (list, p);
	} else {
		int i;
		for (i = 1; i < MAXPID; i++) {
			RDebugPid *p = xnu_get_pid (i);
			if (p) r_list_append (list, p);
		}
	}
#else
	int i, fd;
	char *ptr, cmdline[1024];
	list->free = (RListFree)&r_debug_pid_free;
	/* TODO */
	if (pid) {
		r_list_append (list, r_debug_pid_new ("(current)", pid, 's', 0));
		/* list parents */
		DIR *dh;
		struct dirent *de;
		dh = opendir ("/proc");
		if (dh == NULL) {
			r_list_free (list);
			return NULL;
		}
		//for (i=2; i<39999; i++) {
		while ((de = readdir (dh))) {
			i = atoi (de->d_name); if (!i) continue;
			snprintf (cmdline, sizeof (cmdline), "/proc/%d/status", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1) continue;
			if (read (fd, cmdline, sizeof(cmdline)) == -1) {
				close (fd);
				continue;
			}
			cmdline[sizeof(cmdline) - 1] = '\0';
			ptr = strstr (cmdline, "PPid:");
			if (ptr) {
				int ret, ppid = atoi (ptr + 6);
				close (fd);
				if (i == pid) {
					//eprintf ("PPid: %d\n", ppid);
					r_list_append (list, r_debug_pid_new (
						"(ppid)", ppid, 's', 0));
				}
				if (ppid != pid) continue;
				snprintf (cmdline, sizeof(cmdline) - 1, "/proc/%d/cmdline", ppid);
				fd = open (cmdline, O_RDONLY);
				if (fd == -1) continue;
				ret = read (fd, cmdline, sizeof(cmdline));
				if (ret > 0) {
					cmdline[ret - 1] = '\0';
					r_list_append (list, r_debug_pid_new (
						cmdline, i, 's', 0));
				}
			}
			close (fd);
		}
		closedir (dh);
	} else
	for (i = 2; i < MAXPID; i++) {
		if (!r_sandbox_kill (i, 0)) {
			int ret;
			// TODO: Use slurp!
			snprintf (cmdline, sizeof(cmdline), "/proc/%d/cmdline", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1) continue;
			cmdline[0] = '\0';
			ret = read (fd, cmdline, sizeof(cmdline));
			if (ret > 0) {
				cmdline[ret - 1] = '\0';
				r_list_append (list, r_debug_pid_new (
					cmdline, i, 's', 0));
			}
			close (fd);
		}
	}
#endif
	return list;
}


static RList *r_debug_native_threads (RDebug *dbg, int pid) {
	RList *list = r_list_new ();
	if (list == NULL) {
		eprintf ("No list?\n");
		return NULL;
	}
#if __WINDOWS__ && !__CYGWIN__
	return w32_thread_list (pid, list);
#elif __APPLE__
	return xnu_thread_list (dbg, pid, list);
#elif __linux__
	return linux_thread_list (pid, list);
#else
	eprintf ("TODO: list threads\n");
	r_list_free (list);
	return NULL;
#endif
}

#if __WINDOWS__ && !__CYGWIN__
static int windows_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	int showfpu = false;
	int pid = dbg->pid;
	int tid = dbg->tid;

	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}

	HANDLE thread = w32_open_thread (pid, tid);
	CONTEXT ctx __attribute__ ((aligned (16)));
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext (thread, &ctx)) {
		eprintf ("GetThreadContext: %x\n", (int)GetLastError ());
		CloseHandle(thread);
		return false;
	}
	CloseHandle(thread);
	if (type==R_REG_TYPE_FPU || type==R_REG_TYPE_MMX || type==R_REG_TYPE_XMM) {
	#if __MINGW64__
		eprintf ("TODO: r_debug_native_reg_read fpu/mmx/xmm\n");
	#else
		int i;
		if (showfpu) {
			eprintf ("cwd = 0x%08x  ; control   ", (ut32)ctx.FloatSave.ControlWord);
			eprintf ("swd = 0x%08x  ; status\n", (ut32)ctx.FloatSave.StatusWord);
			eprintf ("twd = 0x%08x ", (ut32)ctx.FloatSave.TagWord);
			eprintf ("eof = 0x%08x\n", (ut32)ctx.FloatSave.ErrorOffset);
			eprintf ("ese = 0x%08x\n", (ut32)ctx.FloatSave.ErrorSelector);
			eprintf ("dof = 0x%08x\n", (ut32)ctx.FloatSave.DataOffset);
			eprintf ("dse = 0x%08x\n", (ut32)ctx.FloatSave.DataSelector);
			eprintf ("mxcr = 0x%08x\n", (ut32)ctx.ExtendedRegisters[24]);
			for (i=0; i<8; i++) {
				ut32 *a = (ut32*) &(ctx.ExtendedRegisters[10*16]);
				a = a + (i * 4);
				eprintf ("xmm%d = %08x %08x %08x %08x  ",i
						, (int)a[0], (int)a[1], (int)a[2], (int)a[3] );
				ut64 *b = (ut64 *)&ctx.FloatSave.RegisterArea[i*10];
				eprintf ("st%d = %lg (0x%08"PFMT64x")\n", i,
					(double)*((double*)&ctx.FloatSave.RegisterArea[i*10]), *b);
			}
		}
	#endif
	}
	if (sizeof(CONTEXT) < size)
		size = sizeof(CONTEXT);

	memcpy (buf, &ctx, size);
	return size;
// XXX this must be defined somewhere else

}
#endif


#if __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__


//Function to read register from Linux, BSD, Android systems
static int bsd_reg_read (RDebug *dbg, int type, ut8* buf, int size) {
	int showfpu = false;
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __i386__ || __x86_64__
#if __KFBSD__
	{
		// TODO
		struct dbreg dbr;
		ret = ptrace (PT_GETDBREGS, pid, (caddr_t)&dbr, sizeof(dbr));
		if (ret != 0) return false;
		// XXX: maybe the register map is not correct, must review
	}
#endif
#endif
		return true;
		break;
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_MMX:
	case R_REG_TYPE_XMM:
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
		R_DEBUG_REG_T regs;
		memset (&regs, 0, sizeof(regs));
		memset (buf, 0, size);
		#if __NetBSD__ || __OpenBSD__
			ret = ptrace (PTRACE_GETREGS, pid, &regs, sizeof (regs));
		#elif __KFBSD__
			ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
		#else
			#warning not implemented for this platform
			ret = 1;
		#endif
		// if perror here says 'no such process' and the
		// process exists still.. is because there's a
		// missing call to 'wait'. and the process is not
		// yet available to accept more ptrace queries.
		if (ret != 0) return false;
		if (sizeof(regs) < size) size = sizeof(regs);
		memcpy (buf, &regs, size);
		return sizeof(regs);
		}
		break;
	}
	return true;
}
#endif // if __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__



// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static int r_debug_native_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1)
		return false;
#if __WINDOWS__ && !__CYGWIN__
	return windows_reg_read (dbg, type, buf, size);
#elif __APPLE__
	return xnu_reg_read (dbg, type, buf, size);
#elif __linux__
	return linux_reg_read (dbg, type, buf, size);
#elif __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__
	return bsd_reg_read (dbg, type, buf, size);
#else
	#warning dbg-native not supported for this platform
	return false;
#endif
}

static int r_debug_native_reg_write (RDebug *dbg, int type, const ut8* buf, int size) {

	// XXX use switch or so
	if (type == R_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
#if __KFBSD__
		return (0 == ptrace (PT_SETDBREGS, dbg->pid,
			(caddr_t)buf, sizeof (struct dbreg)));
#elif __linux__
		return linux_reg_write (dbg, type, buf, size);
#elif __APPLE__
		if (1) return false; //disable until fixed ?? know why this
		return xnu_reg_write (dbg, type, buf, size);
#else
		//eprintf ("TODO: No support for write DRX registers\n");
		#if __WINDOWS__
		int tid = dbg->tid;
		int pid = dbg->pid;
		BOOL ret;
		HANDLE thread;
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		thread = w32_open_thread (pid, tid);
		ret=SetThreadContext (thread, &ctx)? true: false;
		CloseHandle(thread);
		return ret;
		#endif
		return false;
#endif
#else // i386/x86-64
		return false;
#endif
	} else
	if (type == R_REG_TYPE_GPR) {
#if __WINDOWS__ && !__CYGWIN__
		BOOL ret;
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//	eprintf ("EFLAGS =%x\n", ctx.EFlags);
		HANDLE thread = w32_open_thread (dbg->pid, dbg->tid);
		ret = SetThreadContext (thread, &ctx)? true: false;
		CloseHandle (thread);
		return ret;
#elif __linux__
		return linux_reg_write (dbg, type, buf, size);
#elif __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__
		int ret = ptrace (PTRACE_SETREGS, dbg->pid,
			(void*)(size_t)buf, sizeof (R_DEBUG_REG_T));
		if (sizeof (R_DEBUG_REG_T) < size)
			size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? false: true;
#elif __APPLE__
		return xnu_reg_write (dbg, type, buf, size);
#else
#warning r_debug_native_reg_write not implemented
#endif
	} //else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}

#if __KFBSD__
static RList *r_debug_native_sysctl_map (RDebug *dbg) {
	int mib[4];
	size_t len;
	char *buf, *bp, *eb;
	struct kinfo_vmentry *kve;
	RList *list = NULL;
	RDebugMap *map;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_VMMAP;
	mib[3] = dbg->pid;

	if (sysctl (mib, 4, NULL, &len, NULL, 0) != 0) return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL) return (NULL);
	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		free (buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	list = r_debug_map_list_new();
	if (!list) {
		free (buf);
		return NULL;
	}
	while (bp < eb) {
		kve = (struct kinfo_vmentry *)(uintptr_t)bp;
		map = r_debug_map_new (kve->kve_path, kve->kve_start,
					kve->kve_end, kve->kve_protection, 0);
		if (map == NULL) break;
		r_list_append (list, map);
		bp += kve->kve_structsize;
	}
	free (buf);
	return list;
}
#endif

static RDebugMap* r_debug_native_map_alloc (RDebug *dbg, ut64 addr, int size) {

#if __APPLE__

	return xnu_map_alloc (dbg, addr, size);

#elif __WINDOWS__ && !__CYGWIN__
	RDebugMap *map = NULL;
	LPVOID base = NULL;
	HANDLE process = w32_open_process (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	if (process == INVALID_HANDLE_VALUE) {
		return map;
	}
	base = VirtualAllocEx (process, (LPVOID)(size_t)addr,
	  			(SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	CloseHandle (process);
	if (!base) {
		eprintf ("Failed to allocate memory\n");
		return map;
	}
	r_debug_map_sync (dbg);
	map = r_debug_map_get (dbg, (ut64)(size_t)base);
	return map;
#else
	// malloc not implemented for this platform
	return NULL;
#endif
}

static int r_debug_native_map_dealloc (RDebug *dbg, ut64 addr, int size) {
#if __APPLE__

	return xnu_map_dealloc (dbg, addr, size);

#elif __WINDOWS__ && !__CYGWIN__
	HANDLE process = w32_open_process (PROCESS_ALL_ACCESS, FALSE, dbg->tid);
	if (process == INVALID_HANDLE_VALUE) {
		return false;
	}
	int ret = true;
	if (!VirtualFreeEx (process, (LPVOID)(size_t)addr,
			  (SIZE_T)size, MEM_DECOMMIT)) {
		eprintf ("Failed to free memory\n");
		ret = false;
	}
	CloseHandle (process);
	return ret;
#else
    // mdealloc not implemented for this platform
	return false;
#endif
}

#if !__WINDOWS__ && !__APPLE__
static void _map_free(RDebugMap *map) {
	if (!map) return;
	free (map->name);
	free (map->file);
	free (map);
}
#endif

static RList *r_debug_native_map_get (RDebug *dbg) {
	RList *list = NULL;
#if __KFBSD__
	int ign;
	char unkstr[128];
#endif
#if __APPLE__
	list = xnu_dbg_maps (dbg, 0);
#elif __WINDOWS__ && !__CYGWIN__
	list = w32_dbg_maps (dbg); // TODO: moar?
#else
#if __sun
	char path[1024];
	/* TODO: On solaris parse /proc/%d/map */
	snprintf (path, sizeof(path) - 1, "pmap %d > /dev/stderr", ps.tid);
	system (path);
#else
	RDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024];
	char region[100], region2[100], perms[5];
	FILE *fd;
	if (dbg->pid == -1) {
		//eprintf ("r_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}
#if __KFBSD__
	list = r_debug_native_sysctl_map (dbg);
	if (list != NULL) return list;
	snprintf (path, sizeof (path), "/proc/%d/map", dbg->pid);
#else
	snprintf (path, sizeof (path), "/proc/%d/maps", dbg->pid);
#endif
	fd = fopen (path, "r");
	if (!fd) {
		perror (sdb_fmt (0, "Cannot open '%s'", path));
		return NULL;
	}

	list = r_list_new ();
	if (!list) {
		fclose (fd);
		return NULL;
	}
	list->free = (RListFree)_map_free;
	while (!feof (fd)) {
		line[0] = '\0';
		fgets (line, sizeof (line) - 1, fd);
		if (line[0] == '\0') break;
		path[0] = '\0';
		line[strlen (line) - 1] = '\0';
#if __KFBSD__
		// 0x8070000 0x8072000 2 0 0xc1fde948 rw- 1 0 0x2180 COW NC vnode /usr/bin/gcc
		sscanf (line, "%s %s %d %d 0x%s %3s %d %d",
			&region[2], &region2[2], &ign, &ign,
			unkstr, perms, &ign, &ign);
		pos_c = strchr (line, '/');
		if (pos_c) strncpy (path, pos_c, sizeof (path) - 1);
		else path[0] = '\0';
#else
		char null[64]; // XXX: this can overflow
		sscanf (line, "%s %s %s %s %s %[^\n]",
			&region[2], perms, null, null, null, path);

		pos_c = strchr (&region[2], '-');
		if (!pos_c) continue;

		pos_c[-1] = (char)'0'; // xxx. this is wrong
		pos_c[ 0] = (char)'x';
		strncpy (region2, pos_c - 1, sizeof (region2) - 1);
#endif // __KFBSD__
		region[0] = region2[0] = '0';
		region[1] = region2[1] = 'x';

		if (!*path) snprintf (path, sizeof (path), "unk%d", unk++);
		perm = 0;
		for (i = 0; perms[i] && i < 4; i++)
			switch (perms[i]) {
			case 'r': perm |= R_IO_READ; break;
			case 'w': perm |= R_IO_WRITE; break;
			case 'x': perm |= R_IO_EXEC; break;
			}

		map = r_debug_map_new (path, r_num_get (NULL, region),
				r_num_get (NULL, region2), perm, 0);
		if (!map) break;
		map->file = strdup (path);
		r_list_append (list, map);
	}
	fclose (fd);
#endif // __sun
#endif // __WINDOWS
	return list;
}

static RList *r_debug_native_modules_get (RDebug *dbg) {
	char *lastname = NULL;
	RDebugMap *map;
	RListIter *iter, *iter2;
	RList *list, *last;
	int must_delete;
#if __APPLE__
	list = xnu_dbg_maps (dbg, 1);
	if (list && !r_list_empty (list)) {
		return list;
	}
#endif
#if __WINDOWS__
	list = w32_dbg_modules (dbg);
	if (list && !r_list_empty (list)) {
		return list;
	}
#endif
	list = r_debug_native_map_get (dbg);
	if (!list) {
		return NULL;
	}
	last = r_list_new ();
	last->free = (RListFree)r_debug_map_free;
	r_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = strdup (map->name);
		}
		must_delete = 1;
		if (file && *file) {
			if (file[0] == '/') {
				if (lastname) {
					if (strcmp (lastname, file)) {
						must_delete = 0;
					}
				} else {
					must_delete = 0;
				}
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

static int r_debug_native_kill (RDebug *dbg, int pid, int tid, int sig) {
	int ret = false;
	if (pid == 0) pid = dbg->pid;
#if __WINDOWS__ && !__CYGWIN__
	ret = w32_terminate_process (dbg, pid);
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
	if ((r_sandbox_kill (pid, sig) != -1)) ret = true;
	if (errno == 1) ret = -true; // EPERM
#if 0
//	}
#endif
#endif
	return ret;
}

struct r_debug_desc_plugin_t r_debug_desc_plugin_native;
static int r_debug_native_init (RDebug *dbg) {
	dbg->h->desc = r_debug_desc_plugin_native;
#if __WINDOWS__ && !__CYGWIN__
	return w32_dbg_init ();
#else
	return true;
#endif
}

#if __i386__ || __x86_64__
// XXX: wtf cmon this  must use drx.c #if __linux__ too..
static int drx_add (RDebug *dbg, ut64 addr, int rwx) {
	// TODO
	return false;
}

static int drx_del (RDebug *dbg, ut64 addr, int rwx) {
	// TODO
	return false;
}
#endif

static int r_debug_native_drx (RDebug *dbg, int n, ut64 addr, int sz, int rwx, int g) {
#if __i386__ || __x86_64__
	drxt regs[8] = {0};

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

	if (sz == 0) {
		drx_list ((drxt*)&regs);
		return false;
	}
	if (sz<0) { // remove
		drx_set (regs, n, addr, -1, 0, 0);
	} else {
		drx_set (regs, n, addr, sz, rwx, g);
	}
	r_reg_setv (R, "dr0", regs[0]);
	r_reg_setv (R, "dr1", regs[1]);
	r_reg_setv (R, "dr2", regs[2]);
	r_reg_setv (R, "dr3", regs[3]);
	r_reg_setv (R, "dr6", regs[6]);
	r_reg_setv (R, "dr7", regs[7]);
	return true;
#else
	eprintf ("drx: Unsupported platform\n");
#endif
	return false;
}

static int r_debug_native_bp (RBreakpointItem *bp, int set, void *user) {
	if (!bp) return false;
#if __i386__ || __x86_64__
	RDebug *dbg = user;

	if (!bp->hw) return false;

	return set?
		drx_add (dbg, bp->addr, bp->rwx):
		drx_del (dbg, bp->addr, bp->rwx);
#endif
	return false;
}

#if __KFBSD__
#include <sys/un.h>
#include <arpa/inet.h>
static void addr_to_string (struct sockaddr_storage *ss, char *buffer, int buflen) {

	char buffer2[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

	if (buflen > 0)
	switch (ss->ss_family) {
	case AF_LOCAL:
		sun = (struct sockaddr_un *)ss;
		strncpy (buffer, (sun && *sun->sun_path)?
			sun->sun_path: "-", buflen-1);
		break;
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		snprintf (buffer, buflen, "%s:%d", inet_ntoa (sin->sin_addr),
				ntohs (sin->sin_port));
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		if (inet_ntop (AF_INET6, &sin6->sin6_addr, buffer2,
				sizeof (buffer2)) != NULL)
			snprintf (buffer, buflen, "%s.%d", buffer2,
				ntohs (sin6->sin6_port));
		else strcpy (buffer, "-");
		break;
	default:
		*buffer = 0;
		break;
	}
}
#endif

#if __APPLE__

static int getMaxFiles() {
	struct rlimit limit;
	if (getrlimit (RLIMIT_NOFILE, &limit) != 0) {
		return 1024;
	}
	return limit.rlim_cur;
}

static RList *xnu_desc_list (int pid) {
#if TARGET_OS_IPHONE
	return NULL;
#else
#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
	RDebugDesc *desc;
	RList *ret = r_list_new();
	struct vnode_fdinfowithpath vi;
	int i, nb, type = 0;
	int maxfd = getMaxFiles();

	for (i=0 ; i<maxfd; i++) {
		nb = proc_pidfdinfo (pid, i, PROC_PIDFDVNODEPATHINFO, &vi, sizeof (vi));
		if (nb<1) {
			continue;
		}
		if (nb < sizeof (vi)) {
			perror ("too few bytes");
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

#if __WINDOWS__
static RList *win_desc_list (int pid) {
	RDebugDesc *desc;
	RList *ret = r_list_new();
	int i;
	HANDLE processHandle;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	LPVOID buff;
	if (!(processHandle=w32_openprocess(0x0040,FALSE,pid))) {
		eprintf("win_desc_list: Error opening process.\n");
		return NULL;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
	#define SystemHandleInformation 16
	while ((status = w32_ntquerysysteminformation(SystemHandleInformation,handleInfo,handleInfoSize,NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (status) {
		eprintf("win_desc_list: NtQuerySystemInformation failed!\n");
		return NULL;
	}
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		if (handle.ProcessId != pid)
			continue;
		if (handle.ObjectTypeNumber != 0x1c)
			continue;
		if (w32_ntduplicateobject (processHandle, &handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0))
			continue;
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (w32_ntqueryobject(dupHandle,2,objectTypeInfo,0x1000,NULL)) {
			CloseHandle(dupHandle);
			continue;
		}
		objectNameInfo = malloc(0x1000);
		if (w32_ntqueryobject(dupHandle,1,objectNameInfo,0x1000,&returnLength)) {
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (w32_ntqueryobject(dupHandle,1,objectNameInfo,returnLength,NULL)) {
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length) {
			//objectTypeInfo->Name.Length ,objectTypeInfo->Name.Buffer,objectName.Length / 2,objectName.Buffer
			buff=malloc((objectName.Length/2)+1);
			wcstombs(buff,objectName.Buffer,objectName.Length/2);
			desc = r_debug_desc_new (handle.Handle,
					buff, 0, '?', 0);
			if (!desc) break;
			r_list_append (ret, desc);
			free(buff);
		} else {
			buff=malloc((objectTypeInfo->Name.Length / 2)+1);
			wcstombs(buff,objectTypeInfo->Name.Buffer,objectTypeInfo->Name.Length);
			desc = r_debug_desc_new (handle.Handle,
					buff, 0, '?', 0);
			if (!desc) break;
			r_list_append (ret, desc);
			free(buff);
		}
		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}
	free(handleInfo);
	CloseHandle(processHandle);
	return ret;
}
#endif

static RList *r_debug_desc_native_list (int pid) {
// TODO: windows
#if __APPLE__
	return xnu_desc_list (pid);
#elif __WINDOWS__
	return win_desc_list(pid);
#elif __KFBSD__
	RList *ret = NULL;
	int perm, type, mib[4];
	size_t len;
	char *buf, *bp, *eb, *str, path[1024];
	RDebugDesc *desc;
	struct kinfo_file *kve;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_FILEDESC;
	mib[3] = pid;

	if (sysctl (mib, 4, NULL, &len, NULL, 0) != 0) return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL) return (NULL);
	if (sysctl (mib, 4, buf, &len, NULL, 0) != 0) {
		free (buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	ret = r_list_new ();
	if (!ret) {
		free (buf);
		return NULL;
	}
	ret->free = (RListFree) r_debug_desc_free;
	while (bp < eb) {
		kve = (struct kinfo_file *)(uintptr_t)bp;
		bp += kve->kf_structsize;
		if (kve->kf_fd < 0) continue; // Skip root and cwd. We need it ??
		str = kve->kf_path;
		switch (kve->kf_type) {
		case KF_TYPE_VNODE: type = 'v'; break;
		case KF_TYPE_SOCKET:
			type = 's';
			if (kve->kf_sock_domain == AF_LOCAL) {
				struct sockaddr_un *sun =
					(struct sockaddr_un *)&kve->kf_sa_local;
				if (sun->sun_path[0] != 0)
					addr_to_string (&kve->kf_sa_local, path, sizeof(path));
				else
					addr_to_string (&kve->kf_sa_peer, path, sizeof(path));
			} else {
				addr_to_string (&kve->kf_sa_local, path, sizeof(path));
				strcat (path, " ");
				addr_to_string (&kve->kf_sa_peer, path + strlen (path),
						sizeof (path));
			}
			str = path;
			break;
		case KF_TYPE_PIPE: type = 'p'; break;
		case KF_TYPE_FIFO: type = 'f'; break;
		case KF_TYPE_KQUEUE: type = 'k'; break;
		case KF_TYPE_CRYPTO: type = 'c'; break;
		case KF_TYPE_MQUEUE: type = 'm'; break;
		case KF_TYPE_SHM: type = 'h'; break;
		case KF_TYPE_PTS: type = 't'; break;
		case KF_TYPE_SEM: type = 'e'; break;
		case KF_TYPE_NONE:
		case KF_TYPE_UNKNOWN:
		default: type = '-'; break;
		}
		perm = (kve->kf_flags & KF_FLAG_READ)?R_IO_READ:0;
		perm |= (kve->kf_flags & KF_FLAG_WRITE)?R_IO_WRITE:0;
		desc = r_debug_desc_new (kve->kf_fd, str, perm, type,
					kve->kf_offset);
		if (desc == NULL) break;
		r_list_append (ret, desc);
	}

	free (buf);
	return ret;
#elif __linux__
	return linux_desc_list (pid);
#else
#warning list filedescriptors not supported for this platform
	return NULL;
#endif
}

static int r_debug_native_map_protect (RDebug *dbg, ut64 addr, int size, int perms) {
#if __WINDOWS__ && !__CYGWIN__
	DWORD old;
	HANDLE process = w32_open_process (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	// TODO: align pointers
	BOOL ret = VirtualProtectEx (WIN32_PI (process), (LPVOID)(UINT)addr,
	  			size, perms, &old);
	CloseHandle (process);
	return ret;
#elif __APPLE__
	return xnu_map_protect (dbg, addr, size, perms);
#elif __linux__
    // mprotect not implemented for this Linux.. contribs are welcome. use r_egg here?
	return false;
#else
    // mprotect not implemented for this platform
	return false;
#endif
}

static int r_debug_desc_native_open (const char *path) {
	return 0;
}

#if 0
static int r_debug_setup_ownership (int fd, RDebug *dbg) {
	RDebugInfo *info = r_debug_info (dbg, NULL);

	if (!info) {
		eprintf ("Error while getting debug info.\n");
		return -1;
	}
	fchown (fd, info->uid, info->gid);
	r_debug_info_free (info);
  	return 0;
}
#endif

static bool r_debug_gcore (RDebug *dbg, RBuffer *dest) {
#if __APPLE__
	return xnu_generate_corefile (dbg, dest);
#else
	return false;
#endif
}

struct r_debug_desc_plugin_t r_debug_desc_plugin_native = {
	.open = r_debug_desc_native_open,
	.list = r_debug_desc_native_list,
};

struct r_debug_plugin_t r_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
#if __i386__
	.bits = R_SYS_BITS_32,
	.arch = "x86",
	.canstep = 1,
#elif __x86_64__
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1,
#if __linux__
	.canstep = 0, // XXX it's 1 on some platforms...
#else
	.canstep = 1, // XXX it's 1 on some platforms...
#endif
#elif __aarch64__
	.bits = R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = "arm",
	.canstep = 0, // XXX it's 1 on some platforms...
#elif __arm__
	.bits = R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = "arm",
#elif __mips__
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = "mips",
	.canstep = 0,
#elif __powerpc__
	.bits = R_SYS_BITS_32,
	.arch = "ppc",
	.canstep = 1,
#else
	.bits = 0,
	.arch = 0,
	.canstep = 0,
#warning Unsupported architecture
#endif
	.init = &r_debug_native_init,
	.step = &r_debug_native_step,
	.cont = &r_debug_native_continue,
	.contsc = &r_debug_native_continue_syscall,
	.attach = &r_debug_native_attach,
	.detach = &r_debug_native_detach,
	.pids = &r_debug_native_pids,
	.tids = &r_debug_native_tids,
	.threads = &r_debug_native_threads,
	.wait = &r_debug_native_wait,
	.kill = &r_debug_native_kill,
	.frames = &r_debug_native_frames, // rename to backtrace ?
	.reg_profile = (void *)r_debug_native_reg_profile,
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

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_native,
	.version = R2_VERSION
};
#endif // CORELIB

//#endif
#else // DEBUGGER
struct r_debug_plugin_t r_debug_plugin_native = {
	.name = "native",
};

#endif // DEBUGGER
