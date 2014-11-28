/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include "native/drx.c" // x86 specific
#include "native/reg.c" // x86 specific

#if DEBUGGER

#if __UNIX__
# include <errno.h>
# if !defined (__HAIKU__)
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
	if (ret != -1 && siginfo.si_signo>0) {
		//siginfo_t newsiginfo = {0};
		//ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason = R_DBG_REASON_SIGNAL;
		dbg->signum = siginfo.si_signo;
		// siginfo.si_code -> USER, KERNEL or WHAT
#if 0
		eprintf ("[+] SIGNAL %d errno=%d code=%d ret=%d\n",
			siginfo.si_signo, siginfo.si_errno,
			siginfo.si_code, ret2);
#endif
		return R_TRUE;
	}
	return R_FALSE;
#else
	return -1;
#endif
}

#define MAXBT 128

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

#define MACH_ERROR_STRING(ret) \
	(mach_error_string (ret) ? r_str_get (mach_error_string (ret)) : "(unknown)")

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/fcntl.h>
#include <sys/proc.h>

// G3
#if __POWERPC__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/ppc/_types.h>
#include <mach/ppc/thread_status.h>
#define R_DEBUG_REG_T ppc_thread_state_t
#define R_DEBUG_STATE_T PPC_THREAD_STATE
#define R_DEBUG_STATE_SZ PPC_THREAD_STATE_COUNT

// iPhone5
#elif __aarch64
 #include <mach/aarch64/thread_status.h>
 #ifndef AARCH64_THREAD_STATE
 #define AARCH64_THREAD_STATE                1
 #endif
 #ifndef AARCH64_THREAD_STATE64
 #define AARCH64_THREAD_STATE64              6
 #endif
 #define R_DEBUG_REG_T aarch64_thread_state_t
 #define R_DEBUG_STATE_T AARCH64_THREAD_STATE
 #define R_DEBUG_STATE_SZ AARCH64_THREAD_STATE_COUNT

// iPhone
#elif __arm
 #include <mach/arm/thread_status.h>
 #ifndef ARM_THREAD_STATE
 #define ARM_THREAD_STATE                1
 #endif
 #ifndef ARM_THREAD_STATE64
 #define ARM_THREAD_STATE64              6
 #endif
 #define R_DEBUG_REG_T arm_thread_state_t
 #define R_DEBUG_STATE_T ARM_THREAD_STATE
 #define R_DEBUG_STATE_SZ ARM_THREAD_STATE_COUNT
#else

// iMac
/* x86 32/64 */
#include <mach/i386/thread_status.h>
#include <sys/ucontext.h>
#include <mach/i386/_structs.h>

typedef union {
	ut64 x64[21];
	ut32 x32[16];
} R_DEBUG_REG_T;

// APPLE
#define R_DEBUG_STATE_T XXX


//(dbg->bits==64)?x86_THREAD_STATE:_STRUCT_X86_THREAD_STATE32
//#define R_DEBUG_REG_T _STRUCT_X86_THREAD_STATE64
#define R_DEBUG_STATE_SZ ((dbg->bits==R_SYS_BITS_64)?168:64)

#define REG_PC ((dbg->bits==R_SYS_BITS_64)?16:10)
#define REG_FL ((dbg->bits==R_SYS_BITS_64)?17:9)
#define REG_SP (7)
//(dbg->bits==64)?7:7

#if OLDIESHIT
#if __x86_64__
#define R_DEBUG_STATE_T x86_THREAD_STATE
#define R_DEBUG_REG_T _STRUCT_X86_THREAD_STATE64
#define R_DEBUG_STATE_SZ x86_THREAD_STATE_COUNT
#if 0
ut64[21]
        __ut64      rax;
        __ut64      rbx;
        __ut64      rcx;
        __ut64      rdx;
        __ut64      rdi;
        __ut64      rsi;
        __ut64      rbp;
        __ut64      rsp;
        __ut64      r8;
        __ut64      r9;
        __ut64      r10;
        __ut64      r11;
        __ut64      r12;
        __ut64      r13;
        __ut64      r14;
        __ut64      r15;
        __ut64      rip;
        __ut64      rflags;
        __ut64      cs;
        __ut64      fs;
        __ut64      gs;
21*8
#endif
#else
#define R_DEBUG_REG_T _STRUCT_X86_THREAD_STATE32
#define R_DEBUG_STATE_T i386_THREAD_STATE
#define R_DEBUG_STATE_SZ i386_THREAD_STATE_COUNT
#if 0
ut32[16]
16*4
    unsigned int        __eax;
    unsigned int        __ebx;
    unsigned int        __ecx;
    unsigned int        __edx;
    unsigned int        __edi;
    unsigned int        __esi;
    unsigned int        __ebp;
    unsigned int        __esp;
    unsigned int        __ss;
    unsigned int        __eflags;
    unsigned int        __eip;
    unsigned int        __cs;
    unsigned int        __ds;
    unsigned int        __es;
    unsigned int        __fs;
    unsigned int        __gs;
#endif
#endif
#endif
// oldie
#endif

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

#ifdef __ANDROID__
 #if __arm64__ || __aarch64__
# define R_DEBUG_REG_T struct user_pt_regs
#undef PTRACE_GETREGS
#define PTRACE_GETREGS PTRACE_GETREGSET
#undef PTRACE_SETREGS
#define PTRACE_SETREGS PTRACE_SETREGSET
 #else
 # define R_DEBUG_REG_T struct pt_regs
 #endif
#else
#include <sys/user.h>
# if __i386__ || __x86_64__
# define R_DEBUG_REG_T struct user_regs_struct
# elif __arm64__ || __aarch64__
# define R_DEBUG_REG_T struct user_pt_regs
#undef PTRACE_GETREGS
#define PTRACE_GETREGS PTRACE_GETREGSET
#undef PTRACE_SETREGS
#define PTRACE_SETREGS PTRACE_SETREGSET
# elif __arm__
# define R_DEBUG_REG_T struct user_regs
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

#if __APPLE__
// TODO: move into native/
task_t pid_to_task(int pid) {
	static task_t old_pid = -1;
	static task_t old_task = -1;
	task_t task = 0;
	int err;

	/* xlr8! */
	if (old_task!= -1 && old_pid == pid)
		return old_task;

	err = task_for_pid (mach_task_self(), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
		eprintf ("Failed to get task %d for pid %d.\n", (int)task, (int)pid);
		eprintf ("Reason: 0x%x: %s\n", err, (char *)MACH_ERROR_STRING (err));
		eprintf ("You probably need to add user to procmod group.\n"
			" Or chmod g+s radare && chown root:procmod radare\n");
		eprintf ("FMI: http://developer.apple.com/documentation/Darwin/Reference/ManPages/man8/taskgated.8.html\n");
		return -1;
	}
	old_pid = pid;
	old_task = task;
	return task;
}

#if 0
// This is no longer necessary on modern OSXs, anyway it feels nice to keep it here for future hacks
// XXX intel specific -- generalize in r_reg..ease access
#define EFLAGS_TRAP_FLAG 0x100
static inline void debug_arch_x86_trap_set(RDebug *dbg, int foo) {
#if __i386__ || __x86_64__
        R_DEBUG_REG_T regs;
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, (ut8*)&regs, sizeof (regs));
	if (dbg->bits == 64) {
		eprintf ("trap flag: %lld\n", (regs.x64[REG_PC]&0x100));
		if (foo) regs.x64[REG_FL] |= EFLAGS_TRAP_FLAG;
		else regs.x64[REG_FL] &= ~EFLAGS_TRAP_FLAG;
	} else {
		eprintf ("trap flag: %d\n", (regs.x32[REG_PC]&0x100));
		if (foo) regs.x32[REG_FL] |= EFLAGS_TRAP_FLAG;
		else regs.x32[REG_FL] &= ~EFLAGS_TRAP_FLAG;
	}
	r_debug_native_reg_write (dbg, R_REG_TYPE_GPR, (const ut8*)&regs, sizeof (regs));
#endif
}
#endif // __APPLE__
#endif

static int r_debug_native_step(RDebug *dbg) {
	int ret = R_FALSE;
	int pid = dbg->pid;
#if __WINDOWS__
	/* set TRAP flag */
	CONTEXT regs __attribute__ ((aligned (16)));
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, &regs, sizeof (regs));
	regs.EFlags |= 0x100;
	r_debug_native_reg_write (dbg, R_REG_TYPE_GPR, &regs, sizeof (regs));
	r_debug_native_continue (dbg, pid, dbg->tid, dbg->signum);
	ret=R_TRUE;
#elif __APPLE__
	//debug_arch_x86_trap_set (dbg, 1);
	// TODO: not supported in all platforms. need dbg.swstep=
#if __arm__
	ret = ptrace (PT_STEP, pid, (caddr_t)1, 0); //SIGINT);
	if (ret != 0) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING (ret));
		ret = R_FALSE; /* do not wait for events */
	} else ret = R_TRUE;
#else
	#if 0 && __arm__
	if (!dbg->swstep)
		eprintf ("XXX hardware stepping is not supported in arm. set e dbg.swstep=true\n");
	else eprintf ("XXX: software step is not implemented??\n");
	return R_FALSE;
	#endif
	//eprintf ("stepping from pc = %08x\n", (ut32)get_offset("eip"));
	//ret = ptrace (PT_STEP, ps.tid, (caddr_t)get_offset("eip"), SIGSTOP);
	ret = ptrace (PT_STEP, pid, (caddr_t)1, 0); //SIGINT);
	if (ret != 0) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING (ret));
		ret = R_FALSE; /* do not wait for events */
	} else ret = R_TRUE;
#endif
#elif __BSD__
	ret = ptrace (PT_STEP, pid, (caddr_t)1, 0);
	if (ret != 0) {
		perror ("native-singlestep");
		ret = R_FALSE;
	} else ret = R_TRUE;
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
#if __WINDOWS__
	dbg->process_handle = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (dbg->process_handle != (HANDLE)NULL && DebugActiveProcess (pid))
		ret = w32_first_thread (pid);
	else ret = -1;
	ret = w32_first_thread (pid);
#elif __APPLE__ || __KFBSD__
	ret = ptrace (PT_ATTACH, pid, 0, 0);
	if (ret!=-1)
		perror ("ptrace (PT_ATTACH)");
	ret = pid;
#else
	ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret!=-1)
		perror ("ptrace (PT_ATTACH)");
	ret = pid;
#endif
	return ret;
}

static int r_debug_native_detach(int pid) {
#if __WINDOWS__
	return w32_detach (pid)? 0 : -1;
#elif __APPLE__ || __BSD__
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
	void *data = (void*)(size_t)((sig != -1)?sig: dbg->signum);
#if __WINDOWS__
	if (ContinueDebugEvent (pid, tid, DBG_CONTINUE) == 0) {
		print_lasterr ((char *)__FUNCTION__);
		eprintf ("debug_contp: error\n");
		return R_FALSE;
	}
	return tid;
#elif __APPLE__
#if __arm__
	int i, ret, status;
	thread_array_t inferior_threads = NULL;
	unsigned int inferior_thread_count = 0;

// XXX: detach is noncontrollable continue
        ptrace (PT_DETACH, pid, 0, 0);
        ptrace (PT_ATTACH, pid, 0, 0);
#if 0
	ptrace (PT_THUPDATE, pid, (void*)(size_t)1, 0); // 0 = send no signal TODO !! implement somewhere else
	ptrace (PT_CONTINUE, pid, (void*)(size_t)1, 0); // 0 = send no signal TODO !! implement somewhere else
	task_resume (pid_to_task (pid));
	ret = waitpid (pid, &status, 0);
#endif
/*
        ptrace (PT_ATTACHEXC, pid, 0, 0);

        if (task_threads (pid_to_task (pid), &inferior_threads,
			&inferior_thread_count) != KERN_SUCCESS) {
                eprintf ("Failed to get list of task's threads.\n");
		return 0;
        }
        for (i = 0; i < inferior_thread_count; i++)
		thread_resume (inferior_threads[i]);
*/
	return 1;
#else
	//ut64 rip = r_debug_reg_get (dbg, "pc");
	return ptrace (PT_CONTINUE, pid, (void*)(size_t)1,
		(int)(size_t)data) == 0;
#endif
#elif __BSD__
	ut64 pc = r_debug_reg_get (dbg, "pc");
	return ptrace (PTRACE_CONT, pid, (void*)(size_t)pc, (int)data) == 0;
#else
//eprintf ("SIG %d\n", dbg->signum);
	return ptrace (PTRACE_CONT, pid, NULL, data) == 0;
#endif
}

static int r_debug_native_wait(RDebug *dbg, int pid) {
#if __WINDOWS__
	return w32_dbg_wait (dbg, pid);
#else
	int ret, status = -1;
	//printf ("prewait\n");
	if (pid==-1)
		return R_DBG_REASON_UNKNOWN;
	ret = waitpid (pid, &status, 0);
	//printf ("status=%d (return=%d)\n", status, ret);
	// TODO: switch status and handle reasons here
	r_debug_handle_signals (dbg);

	if (WIFSTOPPED (status)) {
		dbg->signum = WSTOPSIG (status);
		status = R_DBG_REASON_SIGNAL;
	} else
	if (status == 0 || ret == -1) {
		status = R_DBG_REASON_DEAD;
	} else {
		if (ret != pid)
			status = R_DBG_REASON_NEW_PID;
		else status = dbg->reason;
	}
	return status;
#endif
}

#if __APPLE__
// XXX
static RDebugPid *darwin_get_pid(int pid) {
	int psnamelen, foo, nargs, mib[3];
	size_t size, argmax = 2048;
	char *curr_arg, *start_args, *iter_args, *end_args;
	char *procargs = NULL;
	char psname[4096];
#if 0
	/* Get the maximum process arguments size. */
	mib[0] = CTL_KERN;
	mib[1] = KERN_ARGMAX;
	size = sizeof(argmax);
	if (sysctl (mib, 2, &argmax, &size, NULL, 0) == -1) {
		eprintf ("sysctl() error on getting argmax\n");
		return NULL;
	}
#endif
	/* Allocate space for the arguments. */
	procargs = (char *)malloc (argmax);
	if (procargs == NULL) {
		eprintf ("getcmdargs(): insufficient memory for procargs %d\n", (int)(size_t)argmax);
		return NULL;
	}

	/*
	 * Make a sysctl() call to get the raw argument space of the process.
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROCARGS2;
	mib[2] = pid;

	size = argmax;
	procargs[0] = 0;
	if (sysctl (mib, 3, procargs, &size, NULL, 0) == -1) {
		if (EINVAL == errno) { // invalid == access denied for some reason
			//eprintf("EINVAL returned fetching argument space\n");
			free (procargs);
			return NULL;
		}
		eprintf ("sysctl(): unspecified sysctl error - %i\n", errno);
		free (procargs);
		return NULL;
	}

	// copy the number of argument to nargs
	memcpy (&nargs, procargs, sizeof(nargs));
	iter_args =  procargs + sizeof(nargs);
	end_args = &procargs[size-30]; // end of the argument space
	if (iter_args >= end_args) {
		eprintf ("getcmdargs(): argument length mismatch");
		free (procargs);
		return NULL;
	}

	//TODO: save the environment variables to envlist as well
	// Skip over the exec_path and '\0' characters.
	// XXX: fix parsing
#if 0
	while (iter_args < end_args && *iter_args != '\0') { iter_args++; }
	while (iter_args < end_args && *iter_args == '\0') { iter_args++; }
#endif
	if (iter_args == end_args) {
		free (procargs);
		return NULL;
	}
	/* Iterate through the '\0'-terminated strings and add each string
	 * to the Python List arglist as a Python string.
	 * Stop when nargs strings have been extracted.  That should be all
	 * the arguments.  The rest of the strings will be environment
	 * strings for the command.
	 */
	curr_arg = iter_args;
	start_args = iter_args; //reset start position to beginning of cmdline
	foo = 1;
	*psname = 0;
	psnamelen = 0;
	while (iter_args < end_args && nargs > 0) {
		if (*iter_args++ == '\0') {
			int alen = strlen (curr_arg);
			if (foo) {
				memcpy (psname, curr_arg, alen+1);
				foo = 0;
			} else {
				psname[psnamelen] = ' ';
				memcpy (psname+psnamelen+1, curr_arg, alen+1);
			}
			psnamelen += alen;
			//printf("arg[%i]: %s\n", iter_args, curr_arg);
			/* Fetch next argument */
			curr_arg = iter_args;
			nargs--;
		}
	}

#if 1
	/*
	 * curr_arg position should be further than the start of the argspace
	 * and number of arguments should be 0 after iterating above. Otherwise
	 * we had an empty argument space or a missing terminating \0 etc.
	 */
	if (curr_arg == start_args || nargs > 0) {
		psname[0] = 0;
//		eprintf ("getcmdargs(): argument parsing failed");
		free (procargs);
		return NULL;
	}
#endif
	return r_debug_pid_new (psname, pid, 's', 0); // XXX 's' ??, 0?? must set correct values
}
#endif

#undef MAXPID
#define MAXPID 69999

static RList *r_debug_native_tids(int pid) {
	printf ("TODO: Threads: \n");
	// T
	return NULL;
}

static RList *r_debug_native_pids(int pid) {
	RList *list = r_list_new ();
#if __WINDOWS__
	return w32_pids (pid, list);
#elif __APPLE__
	if (pid) {
		RDebugPid *p = darwin_get_pid (pid);
		if (p) r_list_append (list, p);
	} else {
		int i;
		for(i=1; i<MAXPID; i++) {
			RDebugPid *p = darwin_get_pid (i);
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
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	rdi->cwd = NULL;// TODO : use readlink
	rdi->exe = NULL;// TODO : use readlink!
	return rdi;
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
#if __WINDOWS__
	return w32_thread_list (pid, list);
#elif __APPLE__
#if __arm__
	#define OSX_PC state.__pc
#elif __arm64__
	#define OSX_PC state.__pc
#elif __POWERPC__
	#define OSX_PC state.srr0
#elif __x86_64__
	#define OSX_PC state.__rip
#undef OSX_PC
#define OSX_PC state.x64[REG_PC]
#else
	#define OSX_PC state.__eip
#undef OSX_PC
#define OSX_PC state.x32[REG_PC]
#endif
	int i, tid; //, err;
	//unsigned int gp_count;
	static thread_array_t inferior_threads = NULL;
	static unsigned int inferior_thread_count = 0;
	R_DEBUG_REG_T state;

	if (task_threads (pid_to_task (pid), &inferior_threads,
			&inferior_thread_count) != KERN_SUCCESS) {
		eprintf ("Failed to get list of task's threads.\n");
		return list;
	}
	for (i = 0; i < inferior_thread_count; i++) {
		tid = inferior_threads[i];
		/*
		   XXX overflow here
		   gp_count = R_DEBUG_STATE_SZ; //sizeof (R_DEBUG_REG_T);
		   if ((err = thread_get_state (tid, R_DEBUG_STATE_T,
		   (thread_state_t) &state, &gp_count)) != KERN_SUCCESS) {
		// eprintf ("debug_list_threads: %s\n", MACH_ERROR_STRING(err));
		OSX_PC = 0;
		}
		 */
		r_list_append (list, r_debug_pid_new ("???", tid, 's', OSX_PC));
	}
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
	eprintf ("TODO\n");
#endif
	return list;
}
// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	int pid = dbg->pid;
#if __WINDOWS__
	CONTEXT ctx __attribute__ ((aligned (16)));
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext (tid2handler (dbg->pid, dbg->tid), &ctx)) {
		eprintf ("GetThreadContext: %x\n", (int)GetLastError ());
		return R_FALSE;
	}
	if (sizeof (CONTEXT) < size)
		size = sizeof (CONTEXT);
#if 0
// TODO: fix missing regs deltas in profile (DRX+..)
#include <r_util.h>
eprintf ("++ EAX = 0x%08x  %d\n", ctx.Eax, r_offsetof (CONTEXT, Eax));
eprintf ("++ EBX = 0x%08x  %d\n", ctx.Ebx, r_offsetof (CONTEXT, Ebx));
eprintf ("++ ECX = 0x%08x  %d\n", ctx.Ecx, r_offsetof (CONTEXT, Ecx));
eprintf ("++ EDX = 0x%08x  %d\n", ctx.Edx, r_offsetof (CONTEXT, Edx));
eprintf ("++ EIP = 0x%08x  %d\n", ctx.Eip, r_offsetof (CONTEXT, Eip));
eprintf ("++ EDI = 0x%08x  %d\n", ctx.Edi, r_offsetof (CONTEXT, Edi));
eprintf ("++ ESI = 0x%08x  %d\n", ctx.Esi, r_offsetof (CONTEXT, Esi));
eprintf ("++ ESP = 0x%08x  %d\n", ctx.Esp, r_offsetof (CONTEXT, Esp));
eprintf ("++ EBP = 0x%08x  %d\n", ctx.Ebp, r_offsetof (CONTEXT, Ebp));
eprintf ("++ CS = 0x%08x  %d\n", ctx.SegCs, r_offsetof (CONTEXT, SegCs));
eprintf ("++ DS = 0x%08x  %d\n", ctx.SegDs, r_offsetof (CONTEXT, SegDs));
eprintf ("++ GS = 0x%08x  %d\n", ctx.SegGs, r_offsetof (CONTEXT, SegGs));
eprintf ("++ FS = 0x%08x  %d\n", ctx.SegFs, r_offsetof (CONTEXT, SegFs));
eprintf ("++ SS = 0x%08x  %d\n", ctx.SegSs, r_offsetof (CONTEXT, SegSs));
eprintf ("++ EFL = 0x%08x  %d\n", ctx.EFlags, r_offsetof (CONTEXT, EFlags));
#endif
	memcpy (buf, &ctx, size);
	return size;
// XXX this must be defined somewhere else
#elif __APPLE__
	int ret;
	thread_array_t inferior_threads = NULL;
	unsigned int inferior_thread_count = 0;
	R_DEBUG_REG_T *regs = (R_DEBUG_REG_T*)buf;
        unsigned int gp_count = R_DEBUG_STATE_SZ; //sizeof (R_DEBUG_REG_T);

	if (size<sizeof (R_DEBUG_REG_T)) {
		eprintf ("Small buffer passed to r_debug_read\n");
		return R_FALSE;
	}
        ret = task_threads (pid_to_task (pid), &inferior_threads, &inferior_thread_count);
        if (ret != KERN_SUCCESS) {
                return R_FALSE;
        }

	int tid = dbg->tid;
	if (tid <0 || tid>=inferior_thread_count) {
		dbg->tid = tid = dbg->pid;
	}
	if (tid == dbg->pid)
		tid = 0;
        if (inferior_thread_count>0) {
                /* TODO: allow to choose the thread */
		gp_count = R_DEBUG_STATE_SZ;

// XXX: kinda spaguetti coz multi-arch
#if __i386__ || __x86_64__
		switch (type) {
		case R_REG_TYPE_SEG:
		case R_REG_TYPE_FLG:
		case R_REG_TYPE_GPR:
			if (dbg->bits== R_SYS_BITS_64) {
				ret = thread_get_state (inferior_threads[tid],
					x86_THREAD_STATE, (thread_state_t) regs,
					&gp_count);
			} else {
				ret = thread_get_state (inferior_threads[tid],
					i386_THREAD_STATE, (thread_state_t) regs,
					&gp_count);
			}
			break;
		case R_REG_TYPE_DRX:
			if (dbg->bits== R_SYS_BITS_64) {
				ret = thread_get_state (inferior_threads[tid],
					x86_DEBUG_STATE64, (thread_state_t)
					regs, &gp_count);
			} else {
				ret = thread_get_state (inferior_threads[tid],
					x86_DEBUG_STATE32, (thread_state_t)
					regs, &gp_count);
			}
			break;
		}
#elif __arm__ || __arm64__ || __aarch64__
		if (dbg->bits==R_SYS_BITS_64) {
			ret = thread_get_state (inferior_threads[tid],
				ARM_THREAD_STATE64, (thread_state_t) regs, &gp_count);
		} else {
			ret = thread_get_state (inferior_threads[tid],
				ARM_THREAD_STATE, (thread_state_t) regs, &gp_count);
				//R_DEBUG_STATE_T, (thread_state_t) regs, &gp_count);
		}
#else
		eprintf ("Unknown architecture\n");
#endif
		if (ret != KERN_SUCCESS) {
                        eprintf ("debug_getregs: Failed to get thread %d %d.error (%x). (%s)\n",
				(int)pid, pid_to_task (pid), (int)ret, MACH_ERROR_STRING (ret));
                        perror ("thread_get_state");
                        return R_FALSE;
                }
        } else eprintf ("There are no threads!\n");
        return sizeof (R_DEBUG_REG_T);
#elif __linux__ || __sun || __NetBSD__ || __KFBSD__ || __OpenBSD__
	int ret;
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
#ifndef __ANDROID__
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
#else
		/* linux-{arm/x86/x64} */
		ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
#endif
		if (ret != 0) {
			// if perror here says 'no such process' and the
			// process exists still.. is because there's a
			// missing call to 'wait'. and the process is not
			// yet available to accept more ptrace queries.
			return R_FALSE;
		}
		if (sizeof (regs) < size)
			size = sizeof (regs);
		memcpy (buf, &regs, size);
		return sizeof (regs);
		}
		break;
	}
	return R_TRUE;
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
#ifndef __ANDROID__
		{
		int i;
		long *val = (long*)buf;
		for (i=0; i<8; i++) { // DR0-DR7
			if (i==4 || i == 5) continue;
			long ret = ptrace (PTRACE_POKEUSER, dbg->pid, r_offsetof (
				struct user, u_debugreg[i]), val[i]); //*(val+i));
			if (ret != 0) {
				eprintf ("ptrace error for dr %d\n", i);
				perror("ptrace");
				//return R_FALSE;
			}
		}
		}
		return sizeof (R_DEBUG_REG_T);
#else
		return R_FALSE;
#endif
#elif __APPLE__
		int ret;
		thread_array_t inferior_threads = NULL;
		unsigned int inferior_thread_count = 0;
		R_DEBUG_REG_T *regs = (R_DEBUG_REG_T*)buf;
		unsigned int gp_count = R_DEBUG_STATE_SZ;

		ret = task_threads (pid_to_task (dbg->pid),
			&inferior_threads, &inferior_thread_count);
		if (ret != KERN_SUCCESS) {
			eprintf ("debug_getregs\n");
			return R_FALSE;
		}

		/* TODO: thread cannot be selected */
		if (inferior_thread_count>0) {
			gp_count = ((dbg->bits == R_SYS_BITS_64))? 44:16;
			// XXX: kinda spaguetti coz multi-arch
			int tid = inferior_threads[0];
#if __i386__ || __x86_64__
			switch (type) {
			case R_REG_TYPE_DRX:
				if (dbg->bits== R_SYS_BITS_64) {
					ret = thread_set_state (tid,
						x86_DEBUG_STATE64, (thread_state_t)
						regs, gp_count);
				} else {
					ret = thread_set_state (tid,
						x86_DEBUG_STATE32, (thread_state_t)
						regs, gp_count);
				}
				break;
			default:
				if (dbg->bits == R_SYS_BITS_64) {
					ret = thread_set_state (tid, x86_THREAD_STATE,
						(thread_state_t) regs, gp_count);
				} else {
					ret = thread_set_state (tid, i386_THREAD_STATE,
						(thread_state_t) regs, gp_count);
				}
			}
#else
			ret = thread_set_state (tid, R_DEBUG_STATE_T, (thread_state_t) regs, &gp_count);
#endif
//if (thread_set_state (inferior_threads[0], R_DEBUG_STATE_T, (thread_state_t) regs, gp_count) != KERN_SUCCESS)
			if (ret != KERN_SUCCESS) {
				eprintf ("debug_setregs: Failed to set thread %d %d.error (%x). (%s)\n",
						(int)dbg->pid, pid_to_task (dbg->pid), (int)ret,
						MACH_ERROR_STRING (ret));
				perror ("thread_set_state");
				return R_FALSE;
			}
		} else eprintf ("There are no threads!\n");
		return sizeof (R_DEBUG_REG_T);
#else
		//eprintf ("TODO: No support for write DRX registers\n");
		#if __WINDOWS__
		int tid = dbg->tid;
		int pid = dbg->pid;
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		return SetThreadContext (tid2handler (pid, tid), &ctx)? R_TRUE: R_FALSE;
		#endif
		return R_FALSE;
#endif
#else // i386/x86-64
		return R_FALSE;
#endif
	} else
	if (type == R_REG_TYPE_GPR) {
		int pid = dbg->pid;
#if __WINDOWS__
		int tid = dbg->tid;
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//	eprintf ("EFLAGS =%x\n", ctx.EFlags);
		return SetThreadContext (tid2handler (pid, tid), &ctx)? R_TRUE: R_FALSE;
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
		int ret;
		thread_array_t inferior_threads = NULL;
		unsigned int inferior_thread_count = 0;
		R_DEBUG_REG_T *regs = (R_DEBUG_REG_T*)buf;
		unsigned int gp_count = R_DEBUG_STATE_SZ;

		ret = task_threads (pid_to_task (pid),
			&inferior_threads, &inferior_thread_count);
		if (ret != KERN_SUCCESS) {
			eprintf ("debug_getregs\n");
			return R_FALSE;
		}

		/* TODO: thread cannot be selected */
		if (inferior_thread_count>0) {
			gp_count = ((dbg->bits == R_SYS_BITS_64))? 44:16;
			// XXX: kinda spaguetti coz multi-arch
			int tid = inferior_threads[0];
#if __i386__ || __x86_64__
			switch (type) {
			case R_REG_TYPE_DRX:
				if (dbg->bits== R_SYS_BITS_64) {
					ret = thread_get_state (inferior_threads[tid],
						x86_DEBUG_STATE64, (thread_state_t)
					regs, &gp_count);
				} else {
					ret = thread_get_state (inferior_threads[tid],
						x86_DEBUG_STATE32, (thread_state_t)
					regs, &gp_count);
				}
				break;
			default:
				if (dbg->bits == R_SYS_BITS_64) {
					ret = thread_set_state (tid, x86_THREAD_STATE,
						(thread_state_t) regs, gp_count);
				} else {
					ret = thread_set_state (tid, i386_THREAD_STATE,
						(thread_state_t) regs, gp_count);
				}
			}
#else
			ret = thread_set_state (inferior_threads[tid],
					R_DEBUG_STATE_T, (thread_state_t) regs, &gp_count);
#endif
//if (thread_set_state (inferior_threads[0], R_DEBUG_STATE_T, (thread_state_t) regs, gp_count) != KERN_SUCCESS)
			if (ret != KERN_SUCCESS) {
				eprintf ("debug_setregs: Failed to set thread %d %d.error (%x). (%s)\n",
						(int)pid, pid_to_task (pid), (int)ret, MACH_ERROR_STRING (ret));
				perror ("thread_set_state");
				return R_FALSE;
			}
		} else eprintf ("There are no threads!\n");
		return sizeof (R_DEBUG_REG_T);
#else
#warning r_debug_native_reg_write not implemented
#endif
	} //else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return R_FALSE;
}

#if __APPLE__
static const char * unparse_inheritance (vm_inherit_t i) {
        switch (i) {
        case VM_INHERIT_SHARE: return "share";
        case VM_INHERIT_COPY: return "copy";
        case VM_INHERIT_NONE: return "none";
        default: return "???";
        }
}

extern int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize);

// TODO: move to p/native/darwin.c
// TODO: this loop MUST be cleaned up
static RList *darwin_dbg_maps (RDebug *dbg) {
	RDebugMap *mr;
	char buf[128];
	int i, print;
	kern_return_t kret;
	vm_region_basic_info_data_64_t info, prev_info;
	mach_vm_address_t prev_address;
	mach_vm_size_t size, prev_size;
	mach_port_t object_name;
	mach_msg_type_number_t count;
	int nsubregions = 0;
	int num_printed = 0;
	size_t address = 0;
	task_t task = pid_to_task (dbg->pid);
	RList *list = r_list_new ();
	// XXX: wrong for 64bits
/*
	count = VM_REGION_BASIC_INFO_COUNT_64;
	kret = mach_vm_region (pid_to_task (dbg->pid), &address, &size, VM_REGION_BASIC_INFO_64,
			(vm_region_info_t) &info, &count, &object_name);
	if (kret != KERN_SUCCESS) {
		printf("No memory regions.\n");
		return;
	}
	memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_64_t));
*/
	size = 4096;
	memset (&prev_info, 0, sizeof (prev_info));
	prev_address = address;
	prev_size = size;
	nsubregions = 1;

	for (i=0; ; i++) {
		int done = 0;

		address = prev_address + prev_size;
		print = 0;

		if (prev_size==0)
			break;
		/* Check to see if address space has wrapped around. */
		if (address == 0)
			done = 1;

		if (!done) {
			count = VM_REGION_BASIC_INFO_COUNT_64;
			kret = mach_vm_region (task, (mach_vm_address_t *)&address,
					&size, VM_REGION_BASIC_INFO_64,
					(vm_region_info_t) &info, &count, &object_name);
			if (kret != KERN_SUCCESS) {
				size = 0;
				print = done = 1;
			}
		}

		if (address != prev_address + prev_size)
			print = 1;

		if ((info.protection != prev_info.protection)
				|| (info.max_protection != prev_info.max_protection)
				|| (info.inheritance != prev_info.inheritance)
				|| (info.shared != prev_info.reserved)
				|| (info.reserved != prev_info.reserved))
			print = 1;

//#if __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0)
		 {
			char module_name[1024];
			module_name[0] = 0;
			int ret = proc_regionfilename (dbg->pid, address, module_name, sizeof (module_name));
			module_name[ret] = 0;

		#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
		if (print && size>0 && prev_info.inheritance != VM_INHERIT_SHARE) {
			snprintf (buf, sizeof (buf), "%s %02x %s/%s/%s %s",
					r_str_rwx_i (xwr2rwx (prev_info.max_protection)), i,
					unparse_inheritance (prev_info.inheritance),
					prev_info.shared ? "shar" : "priv",
					prev_info.reserved ? "reserved" : "not-reserved",
					module_name);
			// TODO: MAPS can have min and max protection rules
			// :: prev_info.max_protection
			mr = r_debug_map_new (buf, prev_address, prev_address+prev_size,
				xwr2rwx (prev_info.protection), 0);
			if (mr == NULL) {
				eprintf ("Cannot create r_debug_map_new\n");
				break;
			}
			r_list_append (list, mr);
		}
}
#if 0
		if (1==0 && rest) { /* XXX never pritn this info here */
			addr = 0LL;
			addr = (ut64) (ut32) prev_address;
			if (num_printed == 0)
				fprintf(stderr, "Region ");
			else    fprintf(stderr, "   ... ");
			fprintf(stderr, " 0x%08llx - 0x%08llx %s (%s) %s, %s, %s",
					addr, addr + prev_size,
					unparse_protection (prev_info.protection),
					unparse_protection (prev_info.max_protection),
					unparse_inheritance (prev_info.inheritance),
					prev_info.shared ? "shared" : " private",
					prev_info.reserved ? "reserved" : "not-reserved");

			if (nsubregions > 1)
				fprintf(stderr, " (%d sub-regions)", nsubregions);

			fprintf(stderr, "\n");

			prev_address = address;
			prev_size = size;
			memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_64_t));
			nsubregions = 1;

			num_printed++;
		} else {
#endif
#if 0
			prev_size += size;
			nsubregions++;
#else
			prev_address = address;
			prev_size = size;
			memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_64_t));
			nsubregions = 1;

			num_printed++;
#endif
			//              }
	}
	return list;
}
#endif

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
	RDebugMap *map = NULL;
	kern_return_t ret;
	unsigned char *base = (unsigned char *)addr;
	boolean_t anywhere = !VM_FLAGS_ANYWHERE;

	if (addr == -1)
		anywhere = VM_FLAGS_ANYWHERE;

	ret = vm_allocate (pid_to_task (dbg->tid),
			(vm_address_t*)&base,
			(vm_size_t)size,
			anywhere);
	if (ret != KERN_SUCCESS) {
		printf("vm_allocate failed\n");
		return NULL;
	}
	r_debug_map_sync (dbg); // update process memory maps
	map = r_debug_map_get (dbg, (ut64)base);
	return map;
#elif __WINDOWS__
	RDebugMap *map = NULL;
	LPVOID base = NULL;
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler (dbg->pid, dbg->tid);
	}
	base = VirtualAllocEx (dbg->process_handle, (LPVOID)addr, (SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		eprintf("Failed to allocate memory\n");
		return map;
	}
	r_debug_map_sync (dbg);
	map = r_debug_map_get (dbg, (ut64)base);
	return map;
#else
	// malloc not implemented for this platform
	return NULL;
#endif
}

static int r_debug_native_map_dealloc(RDebug *dbg, ut64 addr, int size) {
#if __APPLE__
	int ret;
	ret = vm_deallocate (pid_to_task (dbg->tid),
			(vm_address_t)addr,
			(vm_size_t)size);
	if (ret != KERN_SUCCESS) {
		printf("vm_deallocate failed\n");
		return R_FALSE;
	}
	return R_TRUE;
#elif __WINDOWS__
	if (!dbg->process_handle) {
		dbg->process_handle = tid2handler (dbg->pid, dbg->tid);
	}
	if (!VirtualFreeEx (dbg->process_handle, (LPVOID)addr, (SIZE_T)size, MEM_DECOMMIT)) {
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
	list = darwin_dbg_maps (dbg);
#elif __WINDOWS__
	list = w32_dbg_maps (); // TODO: moar?
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

/* TODO: Can I use this as in a coroutine? */
static RList *r_debug_native_frames_x86_32(RDebug *dbg, ut64 at) {
	RRegItem *ri;
	RReg *reg = dbg->reg;
	ut32 i, _esp, esp, ebp2;
	RList *list = r_list_new ();
	RIOBind *bio = &dbg->iob;
	ut8 buf[4];

	list->free = free;
	ri = (at==UT64_MAX)? r_reg_get (reg, "ebp", R_REG_TYPE_GPR): NULL;
	_esp = (ut32) ((ri)? r_reg_get_value (reg, ri): at);
		// TODO: implement [stack] map uptrace method too
	esp = _esp;
	for (i=0; i<MAXBT; i++) {
		bio->read_at (bio->io, esp, (void *)&ebp2, 4);
		if (ebp2 == UT32_MAX)
			break;
		*buf = '\0';
		bio->read_at (bio->io, (ebp2-5)-(ebp2-5)%4, (void *)&buf, 4);

		// TODO: arch_is_call() here and this fun will be portable
		if (buf[(ebp2-5)%4]==0xe8) {
			RDebugFrame *frame = R_NEW (RDebugFrame);
			frame->addr = ebp2;
			frame->size = esp-_esp;
			r_list_append (list, frame);
		}
		esp += 4;
	}
	return list;
}

// XXX: Do this work correctly?
static RList *r_debug_native_frames_x86_64(RDebug *dbg, ut64 at) {
	int i;
	ut8 buf[8];
	RDebugFrame *frame;
	ut64 ptr, ebp2;
	ut64 _rip, _rsp, _rbp;
	RList *list;
	RReg *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;

	_rip = r_reg_get_value (reg, r_reg_get (reg, "rip", R_REG_TYPE_GPR));
	if (at == UT64_MAX) {
		_rsp = r_reg_get_value (reg, r_reg_get (reg, "rsp", R_REG_TYPE_GPR));
		_rbp = r_reg_get_value (reg, r_reg_get (reg, "rbp", R_REG_TYPE_GPR));
	} else {
		_rsp = _rbp = at;
	}

	list = r_list_new ();
	list->free = free;
	bio->read_at (bio->io, _rip, (ut8*)&buf, 8);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Plugin before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp (buf, "\x55\x89\xe5", 3) || !memcmp (buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at (bio->io, _rsp, (ut8*)&ptr, 8) != 8) {
			eprintf ("read error at 0x%08"PFMT64x"\n", _rsp);
			r_list_purge (list);
			free (list);
			return R_FALSE;
		}
		RDebugFrame *frame = R_NEW (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);
		_rbp = ptr;
	}

	for (i=1; i<MAXBT; i++) {
		// TODO: make those two reads in a shot
		bio->read_at (bio->io, _rbp, (ut8*)&ebp2, 8);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at (bio->io, _rbp+8, (ut8*)&ptr, 8);
		if (!ptr || !_rbp)
			break;
		frame = R_NEW (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);
		_rbp = ebp2;
	}
	return list;
}

static RList *r_debug_native_frames(RDebug *dbg, ut64 at) {
	if (dbg->bits == R_SYS_BITS_64)
		return r_debug_native_frames_x86_64 (dbg, at);
	return r_debug_native_frames_x86_32 (dbg, at);
}

// TODO: implement own-defined signals
static int r_debug_native_kill(RDebug *dbg, int pid, int tid, int sig) {
#if __WINDOWS__
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
#if __WINDOWS__
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
	DIR *dd;

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
					st.st_mode & S_IFSOCK ? 'S':
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
		closedir(dd);
	}
#endif
	return ret;
}

#if __APPLE__
vm_prot_t unix_prot_to_darwin(int prot) {
        return ((prot&1<<4)?VM_PROT_READ:0 |
                (prot&1<<2)?VM_PROT_WRITE:0 |
                (prot&1<<1)?VM_PROT_EXECUTE:0);
}
#endif
static int r_debug_native_map_protect (RDebug *dbg, ut64 addr, int size, int perms) {
#if __WINDOWS__
	DWORD old;
	if (!dbg->process_handle) {
			dbg->process_handle = tid2handler (dbg->pid, dbg->tid);
	}
	// TODO: align pointers
  return VirtualProtectEx (WIN32_PI (dbg->process_handle), (LPVOID)(UINT)addr, size, perms, &old);
#elif __APPLE__
	int ret;
	// TODO: align pointers
	ret = vm_protect (pid_to_task (dbg->tid),
			(vm_address_t)addr,
			(vm_size_t)size,
			(boolean_t)0, /* maximum protection */
			VM_PROT_COPY|perms); //unix_prot_to_darwin (perms));
	if (ret != KERN_SUCCESS) {
		printf("vm_protect failed\n");
		return R_FALSE;
	}
	return R_TRUE;
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
	.data = &r_debug_plugin_native
};
#endif // CORELIB

//#endif
#else // DEBUGGER
struct r_debug_plugin_t r_debug_plugin_native = {
	.name = "native",
};

#endif // DEBUGGER
