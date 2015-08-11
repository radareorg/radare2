/* radare - LGPL - Copyright 2009-2015 - pancake */

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

#include "native/bt.c"

#if __UNIX__ || __CYGWIN__
# include <errno.h>
# if !defined (__HAIKU__) && !defined (__CYGWIN__)
#  include <sys/ptrace.h>
# endif
# include <sys/wait.h>
# include <signal.h>
#endif

static int r_debug_native_continue(RDebug *dbg, int pid, int tid, int sig);
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
static int r_debug_native_reg_write(RDebug *dbg, int type, const ut8* buf, int size);




static int r_debug_handle_signals (RDebug *dbg) {
#if __linux__
	siginfo_t siginfo = {0};
	int ret = ptrace (PTRACE_GETSIGINFO, dbg->pid, 0, &siginfo);
	if (ret != -1 && siginfo.si_signo > 0) {
		//siginfo_t newsiginfo = {0};
		//ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason = R_DBG_REASON_SIGNAL;
		dbg->signum = siginfo.si_signo;
		//dbg->stopaddr = siginfo.si_addr;
		//dbg->errno = siginfo.si_errno;
		// siginfo.si_code -> HWBKPT, USER, KERNEL or WHAT
		switch (dbg->signum) {
		case SIGSEGV:
			eprintf ("[+] SIGNAL %d errno=%d addr=%p code=%d ret=%d\n",
				siginfo.si_signo, siginfo.si_errno,
				siginfo.si_addr, siginfo.si_code, ret);
			break;
		default: break;
		}
		return R_TRUE;
	}
	return R_FALSE;
#else
	return -1;
#endif
}


#if __WINDOWS__
#include <windows.h>
#define R_DEBUG_REG_T CONTEXT
#include "native/w32.c"

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
#include "native/xnu/xnu_debug.h"

#elif __sun
#define R_DEBUG_REG_T gregset_t
#undef DEBUGGER
#define DEBUGGER 0
#warning No debugger support for SunOS yet

#elif __linux__
#include <limits.h>

struct user_regs_struct_x86_64 {
  ut64 r15; ut64 r14; ut64 r13; ut64 r12; ut64 rbp; ut64 rbx; ut64 r11;
  ut64 r10; ut64 r9; ut64 r8; ut64 rax; ut64 rcx; ut64 rdx; ut64 rsi;
  ut64 rdi; ut64 orig_rax; ut64 rip; ut64 cs; ut64 eflags; ut64 rsp;
  ut64 ss; ut64 fs_base; ut64 gs_base; ut64 ds; ut64 es; ut64 fs; ut64 gs;
};

struct user_regs_struct_x86_32 {
  ut32 ebx; ut32 ecx; ut32 edx; ut32 esi; ut32 edi; ut32 ebp; ut32 eax;
  ut32 xds; ut32 xes; ut32 xfs; ut32 xgs; ut32 orig_eax; ut32 eip;
  ut32 xcs; ut32 eflags; ut32 esp; ut32 xss;
};

#if __ANDROID__

 #if __arm64__ || __aarch64__
 # define R_DEBUG_REG_T struct user_pt_regs
 # undef PTRACE_GETREGS
 # define PTRACE_GETREGS PTRACE_GETREGSET
 # undef PTRACE_SETREGS
 #define PTRACE_SETREGS PTRACE_SETREGSET
 #else
 # define R_DEBUG_REG_T struct pt_regs
 #endif

#else

#include <sys/user.h>
# if __i386__ || __x86_64__
#   define R_DEBUG_REG_T struct user_regs_struct
# elif __arm64__ || __aarch64__
#   define R_DEBUG_REG_T struct user_pt_regs
#   undef PTRACE_GETREGS
#   define PTRACE_GETREGS PTRACE_GETREGSET
#   undef PTRACE_SETREGS
#   define PTRACE_SETREGS PTRACE_SETREGSET
# elif __arm__
#   define R_DEBUG_REG_T struct user_regs
# elif __mips__

#include <sys/ucontext.h>
typedef ut64 mips64_regs_t [274];
# define R_DEBUG_REG_T mips64_regs_t
#endif
# endif
#else // OS


#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // ARCH

#endif /* IF DEBUGGER */


/* begin of debugger code */
#if DEBUGGER

//this is temporal
#if __APPLE__

static const char *r_debug_native_reg_profile(RDebug *dbg) {
	return xnu_reg_profile (dbg);
}
#else

#include "native/reg.c" // x86 specific

#endif

static int r_debug_native_step(RDebug *dbg) {

	int ret = R_FALSE;
	int pid = dbg->pid;
#if __WINDOWS__ && !__CYGWIN__
	/* set TRAP flag */
	CONTEXT regs __attribute__ ((aligned (16)));
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, (ut8 *)&regs, sizeof (regs));
	regs.EFlags |= 0x100;
	r_debug_native_reg_write (dbg, R_REG_TYPE_GPR, (ut8 *)&regs, sizeof (regs));
	r_debug_native_continue (dbg, pid, dbg->tid, dbg->signum);
	ret = R_TRUE;
	r_debug_handle_signals (dbg);
#elif __APPLE__
	return xnu_step (dbg);
#elif __BSD__
	ret = ptrace (PT_STEP, pid, (caddr_t)1, 0);
	if (ret != 0) {
		perror ("native-singlestep");
		ret = R_FALSE;
	} else ret = R_TRUE;
#elif __CYGWIN__
	#warning "r_debug_native_step not supported on this platform"
	ret = R_FALSE;
#else // linux
	ut64 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	addr = r_debug_reg_get (dbg, "pc");
	ret = ptrace (PTRACE_SINGLESTEP, pid, (void*)(size_t)addr, 0); //addr, data);
	r_debug_handle_signals (dbg);
	if (ret == -1) {
		perror ("native-singlestep");
		ret = R_FALSE;
	} else ret = R_TRUE;
#endif
	return ret;
}

// return thread id
static int r_debug_native_attach(RDebug *dbg, int pid) {
	int ret = -1;
#if __linux__
	int traceflags = 0;
	if (dbg->trace_forks) {
		traceflags |= PTRACE_O_TRACEFORK;
		traceflags |= PTRACE_O_TRACEVFORK;
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->trace_clone) {
		// threads
		traceflags |= PTRACE_O_TRACECLONE;
	}
	//traceflags |= PTRACE_O_TRACESYSGOOD; mark 0x80| on signal event, x86-only
	if (dbg->trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	traceflags |= PTRACE_O_TRACEEXIT;
	if (ptrace (PTRACE_SETOPTIONS, pid, 0, traceflags) == -1) {
		/* ignore ptrace-options errors */
	}
#endif
	if (pid == dbg->pid)
		return pid;
#if __WINDOWS__ && !__CYGWIN__
	dbg->process_handle = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (dbg->process_handle != (HANDLE)NULL && DebugActiveProcess (pid))
		ret = w32_first_thread (pid);
	else ret = -1;
	ret = w32_first_thread (pid);
#elif __CYGWIN__
	#warning "r_debug_native_attach not supported on this platform"
	ret = -1;
#elif __APPLE__ || __KFBSD__
	return xnu_attach (dbg, pid);
#else
	ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret!=-1)
		perror ("ptrace (PT_ATTACH)");
	ret = pid;
#endif
	return ret;
}

static int r_debug_native_detach(int pid) {
#if __WINDOWS__ && !__CYGWIN__
	return w32_detach (pid)? 0 : -1;
#elif __CYGWIN__
	#warning "r_debug_native_detach not supported on this platform"
	return -1;
#elif __APPLE__ || __BSD__
	return xnu_dettach (pid);
#elif __BSD__
	return ptrace (PT_DETACH, pid, NULL, 0);
#else
	return ptrace (PTRACE_DETACH, pid, NULL, NULL);
#endif
}

static int r_debug_native_continue_syscall(RDebug *dbg, int pid, int num) {
// XXX: num is ignored
#if __linux__
	return ptrace (PTRACE_SYSCALL, pid, 0, 0);
#elif __BSD__
	ut64 pc = r_debug_reg_get (dbg, "pc");
	return ptrace (PTRACE_SYSCALL, pid, (void*)(size_t)pc, 0);
#else
	eprintf ("TODO: continue syscall not implemented yet\n");
	return -1;
#endif
}

/* TODO: specify thread? */
/* TODO: must return true/false */
static int r_debug_native_continue(RDebug *dbg, int pid, int tid, int sig) {
#if __WINDOWS__ && !__CYGWIN__
	eprintf("r_debug_native_continue: pid=%08x tid=%08x\n",pid,tid);
	if (ContinueDebugEvent (pid, tid, DBG_CONTINUE) == 0) {
		print_lasterr ((char *)__FUNCTION__);
		eprintf ("debug_contp: error\n");
		return R_FALSE;
	}
	return tid;
#elif __APPLE__
	return xnu_continue (dbg, pid, tid, sig);
#elif __BSD__
	void *data = (void*)(size_t)((sig != -1)?sig: dbg->signum);
	ut64 pc = r_debug_reg_get (dbg, "pc");
	return ptrace (PTRACE_CONT, pid, (void*)(size_t)pc, (int)data) == 0;
#elif __CYGWIN__
	#warning "r_debug_native_continue not supported on this platform"
	return -1;
#else
	void *data = (void*)(size_t)((sig != -1)?sig: dbg->signum);
//eprintf ("SIG %d\n", dbg->signum);
	return ptrace (PTRACE_CONT, pid, NULL, data) == 0;
#endif
}

static int r_debug_native_wait(RDebug *dbg, int pid) {
#if __WINDOWS__ && !__CYGWIN__
	return w32_dbg_wait (dbg, pid);
#else
	int ret, status = -1;
	//printf ("prewait\n");
	if (pid==-1)
		return R_DBG_REASON_UNKNOWN;
	// XXX: this is blocking, ^C will be ignored
	ret = waitpid (pid, &status, 0);
	//printf ("status=%d (return=%d)\n", status, ret);
	// TODO: switch status and handle reasons here
	r_debug_handle_signals (dbg);

	if (WIFSTOPPED (status)) {
		dbg->signum = WSTOPSIG (status);
		status = R_DBG_REASON_SIGNAL;
	} else if (status == 0 || ret == -1) {
		status = R_DBG_REASON_DEAD;
	} else {
		if (ret != pid)
			status = R_DBG_REASON_NEW_PID;
		else status = dbg->reason;
	}
	return status;
#endif
}


#undef MAXPID
#define MAXPID 69999

static RList *r_debug_native_tids(int pid) {
	printf ("TODO: Threads: \n");
	// T
	return NULL;
}

static RList *r_debug_native_pids(int pid) {
	RList *list = r_list_new ();
#if __WINDOWS__ && !__CYGWIN__
	return w32_pids (pid, list);
#elif __APPLE__

	if (pid) {
		RDebugPid *p = xnu_get_pid (pid);
		if (p) r_list_append (list, p);
	} else {
		int i;
		for (i=1; i<MAXPID; i++) {
			RDebugPid *p = xnu_get_pid (i);
			if (p) r_list_append (list, p);
		}
	}
#else
	int i, fd;
	char *ptr, cmdline[1024];
// TODO: new syntax: R_LIST (r_debug_pid_free)
	list->free = (RListFree)&r_debug_pid_free;
	/* TODO */
	if (pid) {
		r_list_append (list, r_debug_pid_new ("(current)", pid, 's', 0));
		/* list parents */
		DIR *dh;
		struct dirent *de;
		dh = opendir ("/proc");
		if (dh == NULL) {
			r_list_purge (list);
			free (list);
			return NULL;
		}
		//for (i=2; i<39999; i++) {
		while ((de = readdir (dh))) {
			i = atoi (de->d_name); if (!i) continue;
			snprintf (cmdline, sizeof (cmdline), "/proc/%d/status", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1)
				continue;
			if (read (fd, cmdline, sizeof (cmdline))==-1) {
				close (fd);
				continue;
			}
			cmdline[sizeof (cmdline)-1] = '\0';
			ptr = strstr (cmdline, "PPid:");
			if (ptr) {
				int ret, ppid = atoi (ptr+6);
				close (fd);
				if (i==pid) {
					//eprintf ("PPid: %d\n", ppid);
					r_list_append (list, r_debug_pid_new (
						"(ppid)", ppid, 's', 0));
				}
				if (ppid != pid)
					continue;
				snprintf (cmdline, sizeof (cmdline)-1, "/proc/%d/cmdline", ppid);
				fd = open (cmdline, O_RDONLY);
				if (fd == -1)
					continue;
				ret = read (fd, cmdline, sizeof (cmdline));
				if (ret>0) {
					cmdline[ret-1] = '\0';
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
			snprintf (cmdline, sizeof (cmdline), "/proc/%d/cmdline", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1)
				continue;
			cmdline[0] = '\0';
			ret = read (fd, cmdline, sizeof (cmdline));
			if (ret>0) {
				cmdline[ret-1] = '\0';
				r_list_append (list, r_debug_pid_new (
					cmdline, i, 's', 0));
			}
			close (fd);
		}
	}
#endif
	return list;
}

static RDebugInfo* r_debug_native_info(RDebug *dbg, const char *arg) {
#if __APPLE__
	return xnu_info (dbg, arg);
#elif __linux__
	char procpid_cmdline[1024];
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	rdi->cwd = NULL;// TODO : use readlink
	rdi->exe = NULL;// TODO : use readlink!
	snprintf (procpid_cmdline, sizeof(procpid_cmdline), "/proc/%d/cmdline", rdi->pid);
	rdi->cmdline = r_file_slurp (procpid_cmdline, NULL);
	return rdi;
#endif
	return NULL;
}

static RList *r_debug_native_threads(RDebug *dbg, int pid) {
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
	int i, fd, thid = 0;
	char *ptr, cmdline[1024];

	if (!pid) {
		r_list_free (list);
		return NULL;
	}
	r_list_append (list, r_debug_pid_new ("(current)", pid, 's', 0));
	/* list parents */

	/* LOL! linux hides threads from /proc, but they are accessible!! HAHAHA */
	//while ((de = readdir (dh))) {
	snprintf (cmdline, sizeof (cmdline), "/proc/%d/task", pid);
	if (r_file_exists (cmdline)) {
		struct dirent *de;
		DIR *dh = opendir (cmdline);
		while ((de = readdir (dh))) {
			int tid = atoi (de->d_name);
			// TODO: get status, pc, etc..
			r_list_append (list, r_debug_pid_new (cmdline, tid, 's', 0));
		}
		closedir (dh);
	} else {
		/* LOL! linux hides threads from /proc, but they are accessible!! HAHAHA */
		//while ((de = readdir (dh))) {
		for (i=pid; i<MAXPID; i++) { // XXX
			snprintf (cmdline, sizeof (cmdline), "/proc/%d/status", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1)
				continue;
			read (fd, cmdline, 1024);
			cmdline[sizeof(cmdline)-1] = '\0';
			ptr = strstr (cmdline, "Tgid:");
			if (ptr) {
				int tgid = atoi (ptr+5);
				if (tgid != pid) {
					close (fd);
					continue;
				}
				(void)read (fd, cmdline, sizeof (cmdline)-1);
				snprintf (cmdline, sizeof (cmdline), "thread_%d", thid++);
				cmdline[sizeof (cmdline)-1] = '\0';
				r_list_append (list, r_debug_pid_new (cmdline, i, 's', 0));
			}
			close (fd);
		}
	}
#else
	eprintf ("TODO: list threads\n");
#endif
	return list;
}


// ********** REG_READ functions for each OS ************
//the reason of this is to not have a huge function in r_debug_native_reg_read 
//with a lot of #if #endif and so on. In this way we can split in different functions


#if __WINDOWS__ && !__CYGWIN__
static int windows_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	int showfpu = R_FALSE;
	int pid = dbg->pid;
	int tid = dbg->tid;

	if (type<-1) {
		showfpu = R_TRUE; // hack for debugging
		type = -type;
	}

	HANDLE hProcess=tid2handler (pid, tid);
	CONTEXT ctx __attribute__ ((aligned (16)));
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext (hProcess, &ctx)) {
		eprintf ("GetThreadContext: %x\n", (int)GetLastError ());
		CloseHandle(hProcess);
		return R_FALSE;
	}
	CloseHandle(hProcess);
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
	if (sizeof (CONTEXT) < size)
		size = sizeof (CONTEXT);

	memcpy (buf, &ctx, size);
	return size;
// XXX this must be defined somewhere else

}
#endif


#if __linux__ || __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__


#define PRINT_FPU(fpregs) \
	eprintf ("cwd = 0x%04x  ; control   ", (fpregs).cwd);\
	eprintf ("swd = 0x%04x  ; status\n", (fpregs).swd);\
	eprintf ("ftw = 0x%04x              ", (fpregs).ftw);\
	eprintf ("fop = 0x%04x\n", fpregs.fop);\
	eprintf ("rip = 0x%016"PFMT64x"  ", (ut64)(fpregs).rip);\
	eprintf ("rdp = 0x%016"PFMT64x"\n", (ut64)(fpregs).rdp);\
	eprintf ("mxcsr = 0x%08x        ", (fpregs).mxcsr);\
	eprintf ("mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)\

#define PRINT_FPU_NOXMM(fpregs) \
	eprintf ("cwd = 0x%04lx  ; control   ", (fpregs).cwd);\
	eprintf ("swd = 0x%04lx  ; status\n", (fpregs).swd);\
	eprintf ("twd = 0x%04lx              ", (fpregs).twd);\
	eprintf ("fip = 0x%04lx          \n", (fpregs).fip);\
	eprintf ("fcs = 0x%04lx              ", (fpregs).fcs);\
	eprintf ("foo = 0x%04lx          \n", (fpregs).foo);\
	eprintf ("fos = 0x%04lx              ", (fpregs).fos)


static void print_fpu (void *f, int r){
	int i;
#if __x86_64__ || __i386__
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct*)f;
#if __x86_64__
	#if !__ANDROID__
		eprintf ("---- x86-64 ----\n");
		PRINT_FPU(fpregs);
		eprintf ("size = 0x%08x\n", (ut32)sizeof (fpregs));
		for (i=0;i<16;i++) {
			ut32 *a = (ut32*)&fpregs.xmm_space;
			a = a + (i * 4);
			eprintf ("xmm%d = %08x %08x %08x %08x   ",i
				, (int)a[0], (int)a[1], (int)a[2], (int)a[3] );
			if (i<8) {
				ut64 *b = (ut64 *)&fpregs.st_space[i*4];
				ut32 *c =(ut32*)&fpregs.st_space;
				float *f=(float *)&fpregs.st_space;
				c=c+(i*4);
				f=f+(i*4);
				eprintf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (%08x)  | %0.3f (%08x) \n", i
					,(double)*((double*)&fpregs.st_space[i*4]), *b, (float)f[0], c[0], (float)f[1], c[1]);
			} else eprintf ("\n");
		}
	#else
		PRINT_FPU(fpregs);
		for(i=0;i<8;i++) {
			ut64 *b = (ut64 *)&fpregs.st_space[i*4];
			ut32 *c =(ut32*)&fpregs.st_space;
			float *f=(float *)&fpregs.st_space;
			c=c+(i*4);
			f=f+(i*4);
			eprintf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (%08x)  | %0.3f (%08x) \n", i
				,(double)*((double*)&fpregs.st_space[i*4]),*b,(float) f[0], c[0], (float) f[1], c[1]);
		}
	#endif	// !__ANDROID__
#elif __i386__
		if (!r) {
			#if !__ANDROID__
				struct user_fpxregs_struct fpxregs = *(struct user_fpxregs_struct*)f;
				eprintf ("---- x86-32 ----\n");
				eprintf ("cwd = 0x%04x  ; control   ", fpxregs.cwd);
				eprintf ("swd = 0x%04x  ; status\n", fpxregs.swd);
				eprintf ("twd = 0x%04x ", fpxregs.twd);
				eprintf ("fop = 0x%04x\n", fpxregs.fop);
				eprintf ("fip = 0x%08x\n", fpxregs.fip);
				eprintf ("fcs = 0x%08x\n", fpxregs.fcs);
				eprintf ("foo = 0x%08x\n", fpxregs.foo);
				eprintf ("fos = 0x%08x\n", fpxregs.fos);
				eprintf ("mxcsr = 0x%08x\n", fpxregs.mxcsr);
				for(i=0;i<8;i++) {
					ut32 *a = (ut32*)(&fpxregs.xmm_space);
					ut64 *b = (ut64 *)(&fpxregs.st_space[i*4]);
					ut32 *c =(ut32*)&fpxregs.st_space;
					float *f = (float *)&fpxregs.st_space;
					a = a + (i * 4);
					eprintf ("xmm%d = %08x %08x %08x %08x   ",i
						, (int)a[0], (int)a[1], (int)a[2], (int)a[3] );
					c=c+(i*4);
					f=f+(i*4);
					eprintf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x)  | %0.3f (0x%08x)\n", i
						,(double)*((double*)(&fpxregs.st_space[i*4])),b[0], f[0], c[0], f[1], c[1]);
				}
			#endif // !__ANDROID__
				return;
		}
		eprintf ("---- x86-32-noxmm ----\n");
		PRINT_FPU_NOXMM(fpregs);
		for(i=0;i<8;i++) {
			ut64 *b = (ut64 *)(&fpregs.st_space[i*4]);
			double *d = (double*)b;
			ut32 *c =(ut32*)&fpregs.st_space;
			float *f=(float *)&fpregs.st_space;
			c=c+(i*4);
			f=f+(i*4);
			eprintf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x)  | %0.3f (0x%08x)\n"
				,i ,d[0] ,b[0] ,f[0] ,c[0] ,f[1] ,c[1]);
		}
#endif // __i386__
#endif // __x86_64__ || __i386__	
}


//Function to read register from Linux, BSD, Android systems
static int linux_bsd_reg_read (RDebug *dbg, int type, ut8* buf, int size) {
	int showfpu = R_FALSE;
	int pid = dbg->pid;
	int ret;
	if (type<-1) {
		showfpu = R_TRUE; // hack for debugging
		type = -type;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __i386__ || __x86_64__
	#if __KFBSD__
	{
		// TODO
		struct dbreg dbr;
		ret = ptrace (PT_GETDBREGS, pid, (caddr_t)&dbr, sizeof (dbr));
		if (ret != 0)
			return R_FALSE;
		// XXX: maybe the register map is not correct, must review
	}
	#elif __linux__
		#if !__ANDROID__
		{
			int i;
			for (i=0; i<8; i++) { // DR0-DR7
				if (i==4 || i == 5) continue;
				long ret = ptrace (PTRACE_PEEKUSER, pid, r_offsetof (
					struct user, u_debugreg[i]), 0);
				memcpy (buf+(i*sizeof(ret)), &ret, sizeof(ret));
			}
			return sizeof (R_DEBUG_REG_T);
		}
		#else
			#warning Android X86 does not support DRX
		#endif
	#endif
#endif
		return R_TRUE;
		break;
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_MMX:
	case R_REG_TYPE_XMM:
#if __linux__
	#if __x86_64__ || __i386__
		{
		int ret1 = 0;
		struct user_fpregs_struct fpregs;
		if (type == R_REG_TYPE_FPU) {
			#if __x86_64__
				#if !__ANDROID__
					ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
					if (showfpu) print_fpu ((void *)&fpregs, 0);
					if (ret1 != 0) {
						return R_FALSE;
					}
					if (sizeof (fpregs) < size) {
						size = sizeof (fpregs);
					}
					memcpy (buf, &fpregs, size);
					return sizeof (fpregs);
				#else
					ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
					if (showfpu) print_fpu ((void *)&fpregs, 0);
					if (ret1 != 0)
						return R_FALSE;
					if (sizeof (fpregs) < size)
						size = sizeof (fpregs);
					memcpy (buf, &fpregs, size);
					return sizeof (fpregs)
				#endif // !__ANDROID__
			#elif __i386__
				#if !__ANDROID__
					struct user_fpxregs_struct fpxregs;
					ret1 = ptrace (PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
					if (ret1==0) {
						if (showfpu) print_fpu ((void *)&fpxregs, 0);
						if (sizeof (fpxregs) < size)
							size = sizeof (fpxregs);
						memcpy (buf, &fpxregs, size);
						return sizeof (fpxregs);
					} else {
						ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
						if (showfpu) print_fpu ((void *)&fpregs, 1);
						if (ret1 != 0)
							return R_FALSE;
						if (sizeof (fpregs) < size)
							size = sizeof (fpregs);
						memcpy (buf, &fpregs, size);
						return sizeof (fpregs);
					}
				#else
					ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
					if (showfpu) print_fpu ((void *)&fpregs, 1);
					if (ret1 != 0)
						return R_FALSE;
					if (sizeof (fpregs) < size)
						size = sizeof (fpregs);
					memcpy (buf, &fpregs, size);
					return sizeof (fpregs);
				#endif // !__ANDROID__
			#endif // __i386__
		}		
		}
	#endif // __x86_64__ || __i386__
	#else
		#warning not implemented for this platform
#endif // __linux__
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
		R_DEBUG_REG_T regs;
		memset (&regs, 0, sizeof (regs));
		memset (buf, 0, size);
		#if __NetBSD__ || __OpenBSD__
			ret = ptrace (PTRACE_GETREGS, pid, &regs, sizeof (regs));
		#elif __KFBSD__
			ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
		#elif __linux__ && __powerpc__
			ret = ptrace (PTRACE_GETREGS, pid, &regs, NULL);
		#elif __linux__ && !__powerpc__
			/* linux-{arm/x86/x64} */
			ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
		#else
			#warning not implemented for this platform
			ret = 1;
		#endif
        ////////////////////////////////////////////////

        //////////////////////////////////
		if (ret != 0) {
			// if perror here says 'no such process' and the
			// process exists still.. is because there's a
			// missing call to 'wait'. and the process is not
			// yet available to accept more ptrace queries.
			return R_FALSE;
		}
		if (sizeof (regs) < size) {
			size = sizeof (regs);
		}
		memcpy (buf, &regs, size);
		return sizeof (regs);
		}
		break;
	}
	return R_TRUE;

}

#endif // if __linux__ || __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__



// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	if (size<1)
		return R_FALSE;
#if __WINDOWS__ && !__CYGWIN__
	return windows_reg_read (dbg, type, buf, size);
#elif __APPLE__
	return xnu_reg_read (dbg, type, buf, size);
#elif __linux__ || __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__
	return linux_bsd_reg_read (dbg, type, buf, size);
#else
	#warning dbg-native not supported for this platform
	return R_FALSE;
#endif
}

static int r_debug_native_reg_write(RDebug *dbg, int type, const ut8* buf, int size) {

	// XXX use switch or so
	if (type == R_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
#if __KFBSD__
		return (0 == ptrace (PT_SETDBREGS, dbg->pid,
			(caddr_t)buf, sizeof (struct dbreg)));
#elif __linux__
// XXX: this android check is only for arm
#if !__ANDROID__
		{
		int i;
		long *val = (long*)buf;
		for (i=0; i<8; i++) { // DR0-DR7
			if (i==4 || i == 5) continue;
			long ret = ptrace (PTRACE_POKEUSER, dbg->pid, r_offsetof (
				struct user, u_debugreg[i]), val[i]); //*(val+i));
			if (ret != 0) {
				eprintf ("ptrace error for dr %d\n", i);
				perror ("ptrace");
				//return R_FALSE;
			}
		}
		}
		return sizeof (R_DEBUG_REG_T);
#else
		return R_FALSE;
#endif
#elif __APPLE__
		if (1) return R_FALSE; //disable until fixed ?? know why this
		return xnu_reg_write (dbg, type, buf, size);
#else
		//eprintf ("TODO: No support for write DRX registers\n");
		#if __WINDOWS__
		int tid = dbg->tid;
		int pid = dbg->pid;
		BOOL ret;
		HANDLE hProcess;
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		hProcess=tid2handler (pid, tid);
		ret=SetThreadContext (hProcess, &ctx)? R_TRUE: R_FALSE;
		CloseHandle(hProcess);
		return ret;
		#endif
		return R_FALSE;
#endif
#else // i386/x86-64
		return R_FALSE;
#endif
	} else
	if (type == R_REG_TYPE_GPR) {
		int pid = dbg->pid;
#if __WINDOWS__ && !__CYGWIN__
		int tid = dbg->tid;
		BOOL ret;
		HANDLE hProcess;
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//	eprintf ("EFLAGS =%x\n", ctx.EFlags);
		hProcess=tid2handler (pid, tid);
		ret=SetThreadContext (hProcess, &ctx)? R_TRUE: R_FALSE;
		CloseHandle(hProcess);
		return ret;
#elif __linux__
		int ret = ptrace (PTRACE_SETREGS, pid, 0, (void*)buf);
		if (sizeof (R_DEBUG_REG_T) < size)
			size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? R_FALSE: R_TRUE;
#elif __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__
		int ret = ptrace (PTRACE_SETREGS, pid, (void*)(size_t)buf, sizeof (R_DEBUG_REG_T));
		if (sizeof (R_DEBUG_REG_T) < size)
			size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? R_FALSE: R_TRUE;
#elif __APPLE__
		return xnu_reg_write (dbg, type, buf, size);
#else
#warning r_debug_native_reg_write not implemented
#endif
	} //else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return R_FALSE;
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

	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0)
		return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL)
		return (NULL);
	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		free (buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	list = r_list_new ();
	while (bp < eb) {
		kve = (struct kinfo_vmentry *)(uintptr_t)bp;
		map = r_debug_map_new (kve->kve_path, kve->kve_start,
				kve->kve_end, kve->kve_protection, 0);
		if (map == NULL)
			break;
		r_list_append (list, map);
		bp += kve->kve_structsize;
	}
	free (buf);
	return list;
}
#endif

static RDebugMap* r_debug_native_map_alloc(RDebug *dbg, ut64 addr, int size) {

#if __APPLE__

	return xnu_map_alloc (dbg, addr, size);

#elif __WINDOWS__ && !__CYGWIN__
	RDebugMap *map = NULL;
	LPVOID base = NULL;
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler (dbg->pid, dbg->tid);
	}
	base = VirtualAllocEx (dbg->process_handle, (LPVOID)(size_t)addr, (SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		eprintf("Failed to allocate memory\n");
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

static int r_debug_native_map_dealloc(RDebug *dbg, ut64 addr, int size) {
#if __APPLE__
	
	return xnu_map_dealloc (dbg, addr, size);

#elif __WINDOWS__ && !__CYGWIN__
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler (dbg->pid, dbg->tid);
	}
	if (!VirtualFreeEx (dbg->process_handle, (LPVOID)(size_t)addr, (SIZE_T)size, MEM_DECOMMIT)) {
		eprintf("Failed to free memory\n");
		return R_FALSE;
	}
	return R_TRUE;
#else
    // mdealloc not implemented for this platform
	return R_FALSE;
#endif
}

static RList *r_debug_native_map_get(RDebug *dbg) {
	RList *list = NULL;
#if __KFBSD__
	int ign;
	char unkstr[128];
#endif
#if __APPLE__
	list = xnu_dbg_maps (dbg);
#elif __WINDOWS__ && !__CYGWIN__
	list = w32_dbg_maps (dbg); // TODO: moar?
#else
#if __sun
	char path[1024];
	/* TODO: On solaris parse /proc/%d/map */
	snprintf (path, sizeof (path)-1, "pmap %d > /dev/stderr", ps.tid);
	system (path);
#else
	RDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024];
	char region[100], region2[100], perms[5];
	FILE *fd;
	if (dbg->pid == -1) {
		eprintf ("r_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}
#if __KFBSD__
	list = r_debug_native_sysctl_map (dbg);
	if (list != NULL)
		return list;
	snprintf (path, sizeof (path), "/proc/%d/map", dbg->pid);
#else
	snprintf (path, sizeof (path), "/proc/%d/maps", dbg->pid);
#endif
	fd = fopen (path, "r");
	if (!fd) {
		perror ("debug_init_maps: /proc");
		return NULL;
	}

	list = r_list_new ();

	while (!feof (fd)) {
		line[0]='\0';
		fgets (line, sizeof (line)-1, fd);
		if (line[0]=='\0')
			break;
		path[0]='\0';
		line[strlen (line)-1]='\0';
#if __KFBSD__
		// 0x8070000 0x8072000 2 0 0xc1fde948 rw- 1 0 0x2180 COW NC vnode /usr/bin/gcc
		sscanf (line, "%s %s %d %d 0x%s %3s %d %d",
			&region[2], &region2[2], &ign, &ign,
			unkstr, perms, &ign, &ign);
		pos_c = strchr (line, '/');
		if (pos_c) strncpy (path, pos_c, sizeof (path)-1);
		else path[0]='\0';
#else
		char null[64]; // XXX: this can overflow
		sscanf (line, "%s %s %s %s %s %s",
			&region[2], perms, null, null, null, path);

		pos_c = strchr (&region[2], '-');
		if (!pos_c)
			continue;

		pos_c[-1] = (char)'0'; // xxx. this is wrong
		pos_c[ 0] = (char)'x';
		strncpy (region2, pos_c-1, sizeof (region2)-1);
#endif // __KFBSD__
		region[0] = region2[0] = '0';
		region[1] = region2[1] = 'x';

		if (!*path)
			snprintf (path, sizeof (path), "unk%d", unk++);

		perm = 0;
		for (i = 0; perms[i] && i < 4; i++)
			switch (perms[i]) {
			case 'r': perm |= R_IO_READ; break;
			case 'w': perm |= R_IO_WRITE; break;
			case 'x': perm |= R_IO_EXEC; break;
			}

		map = r_debug_map_new (path,
			r_num_get (NULL, region),
			r_num_get (NULL, region2),
			perm, 0);
		if (map == NULL)
			break;
#if 0
		mr->ini = get_offset(region);
		mr->end = get_offset(region2);
		mr->size = mr->end - mr->ini;
		mr->bin = strdup(path);
		mr->perms = 0;
		if(!strcmp(path, "[stack]") || !strcmp(path, "[vdso]"))
			mr->flags = FLAG_NOPERM;
		else
			mr->flags = 0;

		for(i = 0; perms[i] && i < 4; i++) {
			switch(perms[i]) {
				case 'r':
					mr->perms |= REGION_READ;
					break;
				case 'w':
					mr->perms |= REGION_WRITE;
					break;
				case 'x':
					mr->perms |= REGION_EXEC;
			}
		}
#endif
		r_list_append (list, map);
	}
	fclose (fd);
#endif // __sun
#endif // __WINDOWS
	return list;
}

// TODO: deprecate???
#if 0
static int r_debug_native_bp_write(int pid, ut64 addr, int size, int hw, int rwx) {
	if (hw) {
		/* implement DRx register handling here */
		return R_TRUE;
	}
	return R_FALSE;
}

/* TODO: rethink */
static int r_debug_native_bp_read(int pid, ut64 addr, int hw, int rwx) {
	return R_TRUE;
}
#endif

// TODO: implement own-defined signals
static int r_debug_native_kill(RDebug *dbg, int pid, int tid, int sig) {
#if __WINDOWS__ && !__CYGWIN__
	// TODO: implement thread support signaling here
	eprintf ("TODO: r_debug_native_kill\n");
#if 0
	HANDLE hProcess; // XXX
	static uint WM_CLOSE = 0x10;
	static bool CloseWindow(IntPtr hWnd) {
		hWnd = FindWindowByCaption (0, "explorer");
		SendMessage(hWnd, WM_CLOSE, NULL, NULL);
		CloseWindow(hWnd);
		return true;
	}
	TerminateProcess (hProcess, 1);
#endif
	return R_FALSE;
#else
	int ret = R_FALSE;
#if 0
	if (thread) {
// XXX this is linux>2.5 specific..ugly
		if (dbg->tid>0 && (ret = tgkill (dbg->pid, dbg->tid, sig))) {
			if (ret != -1)
				ret = R_TRUE;
		}
	} else {
#endif
		if (pid==0) pid = dbg->pid;
		if ((r_sandbox_kill (pid, sig) != -1))
			ret = R_TRUE;
		if (errno == 1) // EPERM
			ret = -R_TRUE;
#if 0
//	}
#endif
	return ret;
#endif
}

struct r_debug_desc_plugin_t r_debug_desc_plugin_native;
static int r_debug_native_init(RDebug *dbg) {
	dbg->h->desc = r_debug_desc_plugin_native;
#if __WINDOWS__ && !__CYGWIN__
	return w32_dbg_init ();
#else
	return R_TRUE;
#endif
}

#if __i386__ || __x86_64__
// XXX: wtf cmon this  must use drx.c #if __linux__ too..
static int drx_add(RDebug *dbg, ut64 addr, int rwx) {
	// TODO
	return R_FALSE;
}

static int drx_del(RDebug *dbg, ut64 addr, int rwx) {
	// TODO
	return R_FALSE;
}
#endif

static int r_debug_native_drx(RDebug *dbg, int n, ut64 addr, int sz, int rwx, int g) {
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
		return R_FALSE;
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
	return R_TRUE;
#else
	eprintf ("drx: Unsupported platform\n");
#endif
	return R_FALSE;
}

static int r_debug_native_bp(RBreakpointItem *bp, int set, void *user) {
	if (!bp)
		return R_FALSE;

#if __i386__ || __x86_64__
	RDebug *dbg = user;

	if (!bp->hw)
		return R_FALSE;

	return set?
		drx_add (dbg, bp->addr, bp->rwx):
		drx_del (dbg, bp->addr, bp->rwx);
#endif
	return R_FALSE;
}

#if __KFBSD__
#include <sys/un.h>
#include <arpa/inet.h>
static void addr_to_string(struct sockaddr_storage *ss, char *buffer, int buflen) {

	char buffer2[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

	if (buflen>0)
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

static RList *r_debug_desc_native_list (int pid) {

	RList *ret = NULL;
// TODO: windows
#if __KFBSD__
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

	if (sysctl (mib, 4, NULL, &len, NULL, 0) != 0)
		return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL)
		return (NULL);
	if (sysctl (mib, 4, buf, &len, NULL, 0) != 0) {
		free (buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	ret = r_list_new ();
	if (ret) {
		ret->free = (RListFree) r_debug_desc_free;
		while (bp < eb) {
			kve = (struct kinfo_file *)(uintptr_t)bp;
			bp += kve->kf_structsize;
			if (kve->kf_fd < 0) // Skip root and cwd. We need it ??
				continue;
			str = kve->kf_path;
			switch (kve->kf_type) {
				case KF_TYPE_VNODE: type = 'v'; break;
				case KF_TYPE_SOCKET:
					type = 's';
					if (kve->kf_sock_domain == AF_LOCAL) {
						struct sockaddr_un *sun =
							(struct sockaddr_un *)&kve->kf_sa_local;
						if (sun->sun_path[0] != 0)
							addr_to_string (&kve->kf_sa_local, path, sizeof (path));
						else
							addr_to_string (&kve->kf_sa_peer, path, sizeof (path));
					} else {
						addr_to_string (&kve->kf_sa_local, path, sizeof (path));
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
			if (desc == NULL)
				break;
			r_list_append (ret, desc);
		}
	}
	free (buf);
#elif __linux__
	char path[512], file[512], buf[512];
	struct dirent *de;
	RDebugDesc *desc;
	int type, perm;
	int len, len2;
	struct stat st;
	DIR *dd = NULL;

	snprintf (path, sizeof (path), "/proc/%i/fd/", pid);
	if (!(dd = opendir (path))) {
		eprintf ("Cannot open /proc\n");
		return NULL;
	}

	if ((ret = r_list_new ())) {
		ret->free = (RListFree) r_debug_desc_free;
		while ((de = (struct dirent *)readdir(dd))) {
			if (de->d_name[0]=='.')
				continue;

			len = strlen (path);
			len2 = strlen (de->d_name);
			if (len+len2+1 >= sizeof (file)) {
				r_list_free (ret);
				closedir (dd);
				eprintf ("Filename is too long");
				return NULL;
			}
			memcpy (file, path, len);
			memcpy (file+len, de->d_name, len2+1);

			memset (buf, 0, sizeof (buf));
			readlink (file, buf, sizeof (buf) - 1);
			type = perm = 0;
			if (stat (file, &st) != -1) {
				type  = st.st_mode & S_IFIFO  ? 'P':
#ifdef S_IFSOCK
					st.st_mode & S_IFSOCK ? 'S':
#endif
					st.st_mode & S_IFCHR  ? 'C':'-';
			}
			if (lstat(path, &st) != -1) {
				if (st.st_mode & S_IRUSR)
					perm |= R_IO_READ;
				if (st.st_mode & S_IWUSR)
					perm |= R_IO_WRITE;
			}
			//TODO: Offset
			desc = r_debug_desc_new (atoi (de->d_name), buf, perm, type, 0);
			if (desc == NULL)
				break;
			r_list_append (ret, desc);
		}
	}
	closedir(dd);
#endif
	return ret;
}

static int r_debug_native_map_protect (RDebug *dbg, ut64 addr, int size, int perms) {

#if __WINDOWS__ && !__CYGWIN__
	DWORD old;
	if (!dbg->process_handle) {
			dbg->process_handle = tid2handler (dbg->pid, dbg->tid);
	}
	// TODO: align pointers
  return VirtualProtectEx (WIN32_PI (dbg->process_handle), (LPVOID)(UINT)addr, size, perms, &old);
#elif __APPLE__
  return xnu_map_protect (dbg, addr, size, perms);
#elif __linux__
    // mprotect not implemented for this Linux.. contribs are welcome. use r_egg here?
	return R_FALSE;
#else
    // mprotect not implemented for this platform
	return R_FALSE;
#endif
}

static int r_debug_desc_native_open (const char *path) {
	return 0;
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
	.arch = R_ASM_ARCH_X86,
	.canstep = 1,
#elif __x86_64__
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = R_ASM_ARCH_X86,
	.canstep = 1,
#elif __arm__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_ARM,
	.canstep = 0, // XXX it's 1 on some platforms...
#elif __aarch64__
	.bits = R_SYS_BITS_64,
	.arch = R_ASM_ARCH_ARM,
	.canstep = 0, // XXX it's 1 on some platforms...
#elif __mips__
	.bits = R_SYS_BITS_64,
	.arch = R_ASM_ARCH_MIPS,
	.canstep = 0,
#elif __powerpc__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_PPC,
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
	.map_protect = r_debug_native_map_protect,
	.breakpoint = r_debug_native_bp,
	.drx = r_debug_native_drx,
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
