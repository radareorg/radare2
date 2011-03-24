/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <signal.h>

static int r_debug_native_continue(int pid, int tid, int sig);
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
static int r_debug_native_reg_write(int pid, int tid, int type, const ut8* buf, int size);

#define DEBUGGER 1
#define MAXBT 128

#if __WINDOWS__
#include <windows.h>
#define R_DEBUG_REG_T CONTEXT
#include "native/w32.c"

#elif __OpenBSD__ || __NetBSD__ || __FreeBSD__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#define R_DEBUG_REG_T struct reg

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

#if __POWERPC__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/ppc/_types.h>
#include <mach/ppc/thread_status.h>
#define R_DEBUG_REG_T ppc_thread_state_t
#define R_DEBUG_STATE_T PPC_THREAD_STATE
#define R_DEBUG_STATE_SZ PPC_THREAD_STATE_COUNT
#elif __arm
#include <mach/arm/thread_status.h>
#define R_DEBUG_REG_T arm_thread_state_t
#define R_DEBUG_STATE_T ARM_THREAD_STATE
#define R_DEBUG_STATE_SZ ARM_THREAD_STATE_COUNT
#else
#include <mach/i386/thread_status.h>
#include <sys/ucontext.h>
#include <mach/i386/_structs.h>

#if __x86_64__
#define R_DEBUG_STATE_T x86_THREAD_STATE
#define R_DEBUG_REG_T _STRUCT_X86_THREAD_STATE64
#define R_DEBUG_STATE_SZ x86_THREAD_STATE_COUNT
#else
#define R_DEBUG_REG_T _STRUCT_X86_THREAD_STATE32
#define R_DEBUG_STATE_T i386_THREAD_STATE
#define R_DEBUG_STATE_SZ i386_THREAD_STATE_COUNT
#endif
#endif

#elif __sun
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#define R_DEBUG_REG_T gregset_t
#undef DEBUGGER
#define DEBUGGER 0
#warning No debugger support for SunOS yet

#elif __linux__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <limits.h>
# if __i386__ || __x86_64__
# define R_DEBUG_REG_T struct user_regs_struct
# elif __arm__
# define R_DEBUG_REG_T struct user_regs
# elif __mips__
#include <sys/ucontext.h>
typedef unsigned long mips64_regs_t [4096];
# define R_DEBUG_REG_T mips64_regs_t
# endif
#else // OS

#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // ARCH

#if DEBUGGER

#if __APPLE__
// TODO: move into native/
task_t pid_to_task(int pid) {
	static task_t old_pid = -1;
	static task_t old_task = -1;
	task_t task = 0;
	int err;

	/* xlr8! */
	if (old_task!= -1) //old_pid != -1 && old_pid == pid)
		return old_task;

	err = task_for_pid (mach_task_self(), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID(task)) {
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

// XXX intel specific -- generalize in r_reg..ease access
#define EFLAGS_TRAP_FLAG 0x100
static inline void debug_arch_x86_trap_set(RDebug *dbg, int foo) {
#if __i386__ || __x86_64__
        R_DEBUG_REG_T regs;
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, (ut8*)&regs, sizeof (regs));
#if __x86_64__
        eprintf ("trap flag: %lld\n", (regs.__rflags&0x100));
        if (foo) regs.__rflags |= EFLAGS_TRAP_FLAG;
        else regs.__rflags &= ~EFLAGS_TRAP_FLAG;
#else
        eprintf ("trap flag: %d\n", (regs.__eflags&0x100));
        if (foo) regs.__eflags |= EFLAGS_TRAP_FLAG;
        else regs.__eflags &= ~EFLAGS_TRAP_FLAG;
#endif
	r_debug_native_reg_write (dbg->pid, dbg->tid, R_REG_TYPE_GPR, (const ut8*)&regs, sizeof (regs));
#endif
}
#endif // __APPLE__

static int r_debug_native_step(RDebug *dbg) {
	int ret = R_FALSE;
	int pid = dbg->pid;
#if __WINDOWS__
	CONTEXT regs __attribute__((aligned (16)));
	/* set TRAP flag */
/*
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, &regs, sizeof (regs));
	regs.EFlags |= 0x100;
	r_debug_native_reg_write (pid, dbg->tid, R_REG_TYPE_GPR, &regs, sizeof (regs));
*/
	r_debug_native_continue (pid, dbg->tid, -1);
#elif __APPLE__
	debug_arch_x86_trap_set (dbg, 1);
	// TODO: not supported in all platforms. need dbg.swstep=
	#if __arm__
	if (!dbg->swstep)
		eprintf ("XXX hardware stepping is not supported in arm. set e dbg.swstep=true\n");
	else eprintf ("XXX: software step is not implemented??\n");
	return R_FALSE;
	#endif
	//eprintf ("stepping from pc = %08x\n", (ut32)get_offset("eip"));
	//ret = ptrace (PT_STEP, ps.tid, (caddr_t)get_offset("eip"), SIGSTOP);
	ret = ptrace (PT_STEP, pid, (caddr_t)1, SIGTRAP); //SIGINT);
	if (ret != 0) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING (ret));
		ret = R_FALSE; /* do not wait for events */
	} else ret = R_TRUE;
#else // linux
	ut32 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	ret = ptrace (PTRACE_SINGLESTEP, pid, addr, 0); //addr, data);
	if (ret == -1) {
		perror ("native-singlestep");
		ret = R_FALSE;
	} else ret = R_TRUE;
#endif
	return ret;
}

// return thread id
static int r_debug_native_attach(int pid) {
	int ret = -1;
#if __WINDOWS__
	HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess != (HANDLE)NULL && DebugActiveProcess (pid)) {
		ret = w32_first_thread (pid);
	} else ret = -1;
	ret = w32_first_thread (pid);
#elif __APPLE__
	// XXX: not necessary in X86??
	ret = ptrace (PT_ATTACH, pid, 0, 0);
	if (ret!=-1) {
		perror ("ptrace(PT_ATTACH)");
		ret = pid;
	}
	ret = pid;
#else
	ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret!=-1)
		ret = pid;
#endif
	return ret;
}

static int r_debug_native_detach(int pid) {
#if __WINDOWS__
	return w32_detach (pid)? 0 : -1;
#elif __APPLE__
	return ptrace (PT_DETACH, pid, NULL, 0);
#else
	return ptrace (PTRACE_DETACH, pid, NULL, NULL);
#endif
}

static int r_debug_native_continue_syscall(int pid, int num) {
#if __linux__
	return ptrace (PTRACE_SYSCALL, pid, 0, 0);
#elif __BSD__
	ut64 pc = 0LL; // XXX
	return ptrace (PTRACE_SYSCALL, pid, pc, 0);
#else
	eprintf ("TODO: continue syscall not implemented yet\n");
	return -1;
#endif
}

/* TODO: specify thread? */
/* TODO: must return true/false */
static int r_debug_native_continue(int pid, int tid, int sig) {
	void *data = NULL;
	if (sig != -1)
		data = (void*)(size_t)sig;
#if __WINDOWS__
	if (ContinueDebugEvent (pid, tid, DBG_CONTINUE) == 0) {
		print_lasterr ((char *)__FUNCTION__);
		eprintf ("debug_contp: error\n");
		return -1;
	}
	return 0;
#elif __APPLE__
        eprintf ("debug_contp: program is now running...\n");
 
	/* XXX */
	/* only stopped with ptrace the first time */
	//ptrace(PT_CONTINUE, pid, 0, 0);
	ptrace (PT_DETACH, pid, 0, 0);
	#if 0
	task_resume (inferior_task); // ???
	thread_resume (inferior_threads[0]);
	#endif
        return 0;
#else
	void *addr = NULL; // eip for BSD
	return ptrace (PTRACE_CONT, pid, addr, data);
#endif
}

static int r_debug_native_wait(int pid) {
#if __WINDOWS__
	return w32_dbg_wait (pid);
#else
	int ret, status = -1;
	//printf ("prewait\n");
	ret = waitpid (pid, &status, 0);
	//printf ("status=%d (return=%d)\n", status, ret);
	// TODO: switch status and handle reasons here
	status = R_DBG_REASON_UNKNOWN;
	return status;
#endif
}

// TODO: why strdup here?
static const char *r_debug_native_reg_profile() {
#if __WINDOWS__
	return strdup (
	"=pc	eip\n"
	"=sp	esp\n"
	"=bp	ebp\n"
	"=a0	eax\n"
	"=a1	ebx\n"
	"=a2	ecx\n"
	"=a3	edi\n"
	"drx	dr0	.32	4	0\n"
	"drx	dr1	.32	8	0\n"
	"drx	dr2	.32	12	0\n"
	"drx	dr3	.32	16	0\n"
	"drx	dr6	.32	20	0\n"
	"drx	dr7	.32	24	0\n"
	/* floating save area 4+4+4+4+4+4+4+80+4 = 112 */
	"seg	gs	.32	132	0\n"
	"seg	fs	.32	136	0\n"
	"seg	es	.32	140	0\n"
	"seg	ds	.32	144	0\n"
	"gpr	edi	.32	156	0\n"
	"gpr	esi	.32	160	0\n"
	"gpr	ebx	.32	164	0\n"
	"gpr	edx	.32	168	0\n"
	"gpr	ecx	.32	172	0\n"
	"gpr	eax	.32	176	0\n"
	"gpr	ebp	.32	180	0\n"
	"gpr	esp	.32	196	0\n"
	"gpr	eip	.32	184	0\n"
	"seg	cs	.32	184	0\n"
	"seg	ds	.32	152	0\n"
	"seg	gs	.32	140	0\n"
	"seg	fs	.32	144	0\n"
	"gpr	eflags	.32	192	0	c1p.a.zstido.n.rv\n" // XXX must be flg
	"seg	ss	.32	200	0\n"
	/* +512 bytes for maximum supoprted extension extended registers */
	);
#elif __POWERPC__ && __APPLE__
	return strdup (
	"=pc	srr0\n"
	"=sr	srr1\n" // status register
	"=a0	r0\n"
	"=a1	r1\n"
	"=a2	r2\n"
	"=a3	r3\n"
#if 0
	"=a4	r4\n"
	"=a5	r5\n"
	"=a6	r6\n"
	"=a7	r7\n"
#endif
	"gpr	srr0	.32	0	0\n"
	"gpr	srr1	.32	4	0\n"
	"gpr	r0	.32	8	0\n"
	"gpr	r1	.32	12	0\n"
	"gpr	r2	.32	16	0\n"
	"gpr	r3	.32	20	0\n"
	"gpr	r4	.32	24	0\n"
	"gpr	r5	.32	28	0\n"
	"gpr	r6	.32	32	0\n"
	"gpr	r7	.32	36	0\n"
	"gpr	r8	.32	40	0\n"
	"gpr	r9	.32	44	0\n"
	"gpr	r10	.32	48	0\n"
	"gpr	r11	.32	52	0\n"
	"gpr	r12	.32	56	0\n"
	"gpr	r13	.32	60	0\n"
	"gpr	r14	.32	64	0\n"
	"gpr	r15	.32	68	0\n"
	"gpr	r16	.32	72	0\n"
	"gpr	r17	.32	76	0\n"
	"gpr	r18	.32	80	0\n"
	"gpr	r19	.32	84	0\n"
	"gpr	r20	.32	88	0\n"
	"gpr	r21	.32	92	0\n"
	"gpr	r22	.32	96	0\n"

	"gpr	r23	.32	100	0\n"
	"gpr	r24	.32	104	0\n"
	"gpr	r25	.32	108	0\n"
	"gpr	r26	.32	112	0\n"
	"gpr	r27	.32	116	0\n"
	"gpr	r28	.32	120	0\n"
	"gpr	r29	.32	124	0\n"
	"gpr	r30	.32	128	0\n"
	"gpr	r31	.32	132	0\n"
	"gpr	cr	.32	136	0\n"
	"gpr	xer	.32	140	0\n"
	"gpr	lr	.32	144	0\n"
	"gpr	ctr	.32	148	0\n"
	"gpr	mq	.32	152	0\n"
	"gpr	vrsave	.32	156	0\n"
	);
#elif __i386__
	return strdup (
	"=pc	eip\n"
	"=sp	esp\n"
	"=bp	ebp\n"
	"=a0	eax\n"
	"=a1	ebx\n"
	"=a2	ecx\n"
	"=a3	edi\n"
	"gpr	eip	.32	48	0\n"
	"gpr	ip	.16	48	0\n"
	"gpr	oeax	.32	44	0\n"
	"gpr	eax	.32	24	0\n"
	"gpr	ax	.16	24	0\n"
	"gpr	ah	.8	24	0\n"
	"gpr	al	.8	25	0\n"
	"gpr	ebx	.32	0	0\n"
	"gpr	bx	.16	0	0\n"
	"gpr	bh	.8	0	0\n"
	"gpr	bl	.8	1	0\n"
	"gpr	ecx	.32	4	0\n"
	"gpr	cx	.16	4	0\n"
	"gpr	ch	.8	4	0\n"
	"gpr	cl	.8	5	0\n"
	"gpr	edx	.32	8	0\n"
	"gpr	dx	.16	8	0\n"
	"gpr	dh	.8	8	0\n"
	"gpr	dl	.8	9	0\n"
	"gpr	esp	.32	60	0\n"
	"gpr	sp	.16	60	0\n"
	"gpr	ebp	.32	20	0\n"
	"gpr	bp	.16	20	0\n"
	"gpr	esi	.32	12	0\n"
	"gpr	si	.16	12	0\n"
	"gpr	edi	.32	16	0\n"
	"gpr	di	.16	16	0\n"
	"seg	xfs	.32	36	0\n"
	"seg	xgs	.32	40	0\n"
	"seg	xcs	.32	52	0\n"
	"seg	cs	.16	52	0\n"
	"seg	xss	.32	52	0\n"
	"gpr	eflags	.32	56	0	c1p.a.zstido.n.rv\n"
	"gpr	flags	.16	56	0\n"
	"flg	carry	.1	.448	0\n"
	"flg	flag_p	.1	.449	0\n"
	"flg	flag_a	.1	.450	0\n"
	"flg	zero	.1	.451	0\n"
	"flg	sign	.1	.452	0\n"
	"flg	flag_t	.1	.453	0\n"
	"flg	flag_i	.1	.454	0\n"
	"flg	flag_d	.1	.455	0\n"
	"flg	flag_o	.1	.456	0\n"
	"flg	flag_r	.1	.457	0\n"
	"drx	dr0	.32	0	0\n"
	"drx	dr1	.32	4	0\n"
	"drx	dr2	.32	8	0\n"
	"drx	dr3	.32	12	0\n"
	//"drx	dr4	.32	16	0\n"
	//"drx	dr5	.32	20	0\n"
	"drx	dr6	.32	24	0\n"
	"drx	dr7	.32	28	0\n"
	);
#elif __x86_64__ && __APPLE__
	return strdup (
	"=pc	rip\n"
	"=sp	rsp\n"
	"=bp	rbp\n"
	"=a0	rax\n"
	"=a1	rbx\n"
	"=a2	rcx\n"
	"=a3	rdx\n"
	"# no profile defined for x86-64\n"
	"gpr	rax	.64	0	0\n"
	"gpr	rbx	.64	8	0\n"
	"gpr	rcx	.64	16	0\n"
	"gpr	rdx	.64	24	0\n"
	"gpr	rdi	.64	32	0\n"
	"gpr	rsi	.64	40	0\n"
	"gpr	rbp	.64	48	0\n"
	"gpr	rsp	.64	56	0\n"
	"gpr	r8	.64	64	0\n"
	"gpr	r9	.64	72	0\n"
	"gpr	r10	.64	80	0\n"
	"gpr	r11	.64	88	0\n"
	"gpr	r12	.64	96	0\n"
	"gpr	r13	.64	104	0\n"
	"gpr	r14	.64	112	0\n"
	"gpr	r15	.64	120	0\n"
	"gpr	rip	.64	128	0\n"
	"gpr	rflags	.64	136	0	c1p.a.zstido.n.rv\n"
	"seg	cs	.64	144	0\n"
	"seg	fs	.64	152	0\n"
	"seg	gs	.64	160	0\n"
#if 0
	"drx	dr0	.32	0	0\n"
	"drx	dr1	.32	4	0\n"
	"drx	dr2	.32	8	0\n"
	"drx	dr3	.32	12	0\n"
	"drx	dr6	.32	24	0\n"
	"drx	dr7	.32	28	0\n"
#endif
	);
#elif __x86_64__
	return strdup (
	"=pc	rip\n"
	"=sp	rsp\n"
	"=bp	rbp\n"
	"=a0	rax\n"
	"=a1	rbx\n"
	"=a2	rcx\n"
	"=a3	rdx\n"
	"# no profile defined for x86-64\n"
	"gpr	r15	.64	0	0\n"
	"gpr	r14	.64	8	0\n"
	"gpr	r13	.64	16	0\n"
	"gpr	r12	.64	24	0\n"
	"gpr	rbp	.64	32	0\n"
	"gpr	rbx	.64	40	0\n"
	"gpr	r11	.64	48	0\n"
	"gpr	r10	.64	56	0\n"
	"gpr	r9	.64	64	0\n"
	"gpr	r8	.64	72	0\n"
	"gpr	rax	.64	80	0\n"
	"gpr	rcx	.64	88	0\n"
	"gpr	rdx	.64	96	0\n"
	"gpr	rsi	.64	104	0\n"
	"gpr	rdi	.64	112	0\n"
	"gpr	oeax	.64	120	0\n"
	"gpr	rip	.64	128	0\n"
	"seg	cs	.64	136	0\n"
	//"flg	eflags	.64	144	0\n"
	"gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
	"gpr	rsp	.64	152	0\n"
	"seg	ss	.64	160	0\n"
	"seg	fs_base	.64	168	0\n"
	"seg	gs_base	.64	176	0\n"
	"seg	ds	.64	184	0\n"
	"seg	es	.64	192	0\n"
	"seg	fs	.64	200	0\n"
	"seg	gs	.64	208	0\n"
	"drx	dr0	.32	0	0\n"
	"drx	dr1	.32	4	0\n"
	"drx	dr2	.32	8	0\n"
	"drx	dr3	.32	12	0\n"
	"drx	dr6	.32	24	0\n"
	"drx	dr7	.32	28	0\n"
	);
#elif __arm__
	return strdup (
	"=pc	r15\n"
	"=sp	r14\n" // XXX
	"=a0	r0\n"
	"=a1	r1\n"
	"=a2	r2\n"
	"=a3	r3\n"
	"gpr	lr	.32	56	0\n" // r14
	"gpr	pc	.32	60	0\n" // r15

	"gpr	r0	.32	0	0\n"
	"gpr	r1	.32	4	0\n"
	"gpr	r2	.32	8	0\n"
	"gpr	r3	.32	12	0\n"
	"gpr	r4	.32	16	0\n"
	"gpr	r5	.32	20	0\n"
	"gpr	r6	.32	24	0\n"
	"gpr	r7	.32	28	0\n"
	"gpr	r8	.32	32	0\n"
	"gpr	r9	.32	36	0\n"
	"gpr	r10	.32	40	0\n"
	"gpr	r11	.32	44	0\n"
	"gpr	r12	.32	48	0\n"
	"gpr	r13	.32	52	0\n"
	"gpr	r14	.32	56	0\n"
	"gpr	r15	.32	60	0\n"
	"gpr	r16	.32	64	0\n"
	"gpr	r17	.32	68	0\n"
	);
#else
#warning NO DEBUGGER REGISTERS PROFILE DEFINED
	return NULL;
#endif
}

/*
	TODO: list all pids in linux and bsd.. osx seems to be strange
	int i;
	for (i=1; i<9999; i++) {
		if (!kill (i, 0))
			r_list_append (list, r_debug_pid_new ("???", i, 's', 0));
	}
*/

#if __APPLE__
// XXX
static RDebugPid *darwin_get_pid(int pid) {
	int foo, nargs, mib[3];
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
	psname[0] = 0;
	while (iter_args < end_args && nargs > 0) {
		if (*iter_args++ == '\0') {
			if (foo) {
				strcpy (psname, curr_arg);
				foo = 0;
			} else {
				strcat (psname, " ");
				strcat (psname, curr_arg);
			}
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
		if (dh == NULL)
			return NULL;
		//for (i=2; i<39999; i++) {
		while ((de = readdir (dh))) {
			i = atoi (de->d_name); if (!i) continue;
			snprintf (cmdline, sizeof (cmdline), "/proc/%d/status", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1)
				continue;
			read (fd, cmdline, 1024);
			cmdline[1023] = '\0';
			ptr = strstr (cmdline, "PPid: ");
			if (ptr) {
				int ppid = atoi (ptr+6);
				close (fd);
				if (ppid != pid)
					continue;
				snprintf (cmdline, sizeof (cmdline), "/proc/%d/cmdline", ppid);
				fd = open (cmdline, O_RDONLY);
				if (fd == -1)
					continue;
				read (fd, cmdline, 1024);
				cmdline[1023] = '\0';
				r_list_append (list, r_debug_pid_new (cmdline, i, 's', 0));
			}
			close (fd);
		}
		closedir (dh);
	} else
	for (i=2; i<MAXPID; i++) {
		if (!kill (i, 0)) {
			// TODO: Use slurp!
			snprintf (cmdline, sizeof (cmdline), "/proc/%d/cmdline", i);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1)
				continue;
			cmdline[0] = '\0';
			read (fd, cmdline, sizeof (cmdline));
			cmdline[sizeof (cmdline)-1] = '\0';
			close (fd);
			r_list_append (list, r_debug_pid_new (cmdline, i, 's', 0));
		}
	}
#endif
	return list;
}

static RList *r_debug_native_threads(int pid) {
	RList *list = r_list_new ();
	if (list == NULL) {
		eprintf ("No list?\n");
		return NULL;
	}
#if __WINDOWS__
	return w32_thread_list (pid, list);
#elif __APPLE__
#if __arm__                 
	#define OSX_PC state.r15
#elif __POWERPC__
	#define OSX_PC state.srr0
#elif __x86_64__
	#define OSX_PC state.__rip
#else
	#define OSX_PC state.__eip
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

	if (!pid)
		return NULL;
	r_list_append (list, r_debug_pid_new ("(current)", pid, 's', 0));
	/* list parents */
	
	/* LOL! linux hides threads from /proc, but they are accessible!! HAHAHA */
	//while ((de = readdir (dh))) {
	snprintf (cmdline, sizeof (cmdline), "/proc/%d/task", pid);
	if (r_file_exist (cmdline)) {
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
			close (fd);
			cmdline[sizeof(cmdline)-1] = '\0';
			ptr = strstr (cmdline, "Tgid:");
			if (ptr) {
				int tgid = atoi (ptr+5);
				if (tgid != pid)
					continue;
				read (fd, cmdline, sizeof(cmdline)-1);
				sprintf (cmdline, "thread_%d", thid++);
				cmdline[sizeof(cmdline)-1] = '\0';
				r_list_append (list, r_debug_pid_new (cmdline, i, 's', 0));
			}
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
		eprintf ("GetThreadContext: %x\n", (int)GetLastError());
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

	if (size<sizeof(R_DEBUG_REG_T)) {
		eprintf ("Small buffer passed to r_debug_read\n");
		return R_FALSE;
	}
        ret = task_threads (pid_to_task (pid), &inferior_threads, &inferior_thread_count);
        if (ret != KERN_SUCCESS) {
                eprintf ("debug_getregs\n");
                return R_FALSE;
        }

        if (inferior_thread_count>0) {
                /* TODO: allow to choose the thread */
		gp_count = R_DEBUG_STATE_SZ;
                if (thread_get_state (inferior_threads[0], R_DEBUG_STATE_T,
				(thread_state_t) regs, &gp_count) != KERN_SUCCESS) {
                        eprintf ("debug_getregs: Failed to get thread %d %d.error (%x). (%s)\n",
				(int)pid, pid_to_task (pid), (int)ret, MACH_ERROR_STRING (ret));
                        perror ("thread_get_state");
                        return R_FALSE;
                }
        } else eprintf ("There are no threads!\n");
        return sizeof (R_DEBUG_REG_T);
#elif __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
	int ret; 
	switch (type) {
	case R_REG_TYPE_DRX:
#ifdef __FreeBSD__
	{
		// TODO
		struct dbreg dbr;
		ret = ptrace (PTRACE_GETDBREGS, pid, &dbr, sizeof (dbr));
		if (ret != 0)
			return R_FALSE;
		// XXX: maybe the register map is not correct, must review
	}
#elif __linux__
	{
		int i;
		for (i=0; i<7; i++) { // DR0-DR7
			ret = ptrace (PTRACE_PEEKUSER, pid, r_offsetof (
				struct user, u_debugreg[i]), 0);
			if (ret != 0)
				return R_FALSE;
			memcpy (buf+(i*4), &ret, 4);
		}
	}
#else
		return R_FALSE;
#endif
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
		R_DEBUG_REG_T regs;
		memset (&regs, 0, sizeof (regs));
		memset (buf, 0, size);
#if __NetBSD__ || __FreeBSD__ || __OpenBSD__
		ret = ptrace (PTRACE_GETREGS, pid, &regs, sizeof (regs));
#elif __linux__ && __powerpc__
		ret = ptrace (PTRACE_GETREGS, pid, &regs, NULL);
#else
		/* linux/arm/x86/x64 */
		ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
#endif
		if (ret != 0)
			return R_FALSE;
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

static int r_debug_native_reg_write(int pid, int tid, int type, const ut8* buf, int size) {
	// XXX use switch or so
	if (type == R_REG_TYPE_DRX) {
#ifdef __FreeBSD__
		return (0 == ptrace (PTRACE_SETDBREGS, dbg->pid, buf, sizeof (struct dbreg)));
#elif __linux__
		{
		int i;
		ut32 *val = (ut32 *)buf;
		for (i=0; i<7; i++) { // DR0-DR7
			ptrace (PTRACE_POKEUSER, pid, r_offsetof (
				struct user, u_debugreg[i]), *(val+i));
			//if (ret != 0)
			//	return R_FALSE;
		}
		}
#else
		eprintf ("TODO: add support for write DRX registers\n");
		return R_FALSE;
#endif
	} else
	if (type == R_REG_TYPE_GPR) {
#if __WINDOWS__
		CONTEXT ctx __attribute__((aligned (16)));
		memcpy (&ctx, buf, sizeof (CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//	eprintf ("EFLAGS =%x\n", ctx.EFlags);
		return SetThreadContext (tid2handler (pid, tid), &ctx)? R_TRUE: R_FALSE;
#elif __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
		int ret = ptrace (PTRACE_SETREGS, pid, 0, buf);
		if (sizeof (R_DEBUG_REG_T) < size)
			size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? R_FALSE: R_TRUE;
#elif __APPLE__
		int ret; 
		thread_array_t inferior_threads = NULL;
		unsigned int inferior_thread_count = 0;
		R_DEBUG_REG_T *regs = (R_DEBUG_REG_T*)buf;
		unsigned int gp_count = R_DEBUG_STATE_SZ;

		ret = task_threads (pid_to_task (pid), &inferior_threads, &inferior_thread_count);
		if (ret != KERN_SUCCESS) {
			eprintf ("debug_getregs\n");
			return R_FALSE;
		}

		if (inferior_thread_count>0) {
			/* TODO: allow to choose the thread */
			gp_count = R_DEBUG_STATE_SZ; //sizeof (R_DEBUG_REG_T)/sizeof(size_t);
			if (thread_set_state (inferior_threads[0], R_DEBUG_STATE_T,
					(thread_state_t) regs, gp_count) != KERN_SUCCESS) {
				eprintf ("debug_getregs: Failed to get thread %d %d.error (%x). (%s)\n",
					(int)pid, pid_to_task (pid), (int)ret, MACH_ERROR_STRING (ret));
				perror ("thread_get_state");
				return R_FALSE;
			}
		} else eprintf ("There are no threads!\n");
		return sizeof (R_DEBUG_REG_T);
#else
#warning r_debug_native_reg_write not implemented
#endif
	} else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
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

// TODO: move to p/native/darwin.c
// TODO: this loop MUST be cleaned up
static RList *darwin_dbg_maps (RDebug *dbg) {
	RDebugMap *mr;
	RList *list = r_list_new ();

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
	// XXX: wrong for 64bits
	size_t address = 0;
	task_t task = pid_to_task (dbg->pid);
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

		#define xwr2rwx(x) ((x&1)<<2) && (x&2) && ((x&4)>>2)
		if (print) {
			sprintf (buf, "%s %02x %s/%s/%s",
					r_str_rwx_i (xwr2rwx (prev_info.max_protection)), i,
					unparse_inheritance (prev_info.inheritance),
					prev_info.shared ? "shar" : "priv",
					prev_info.reserved ? "reserved" : "not-reserved");
			// TODO: MAPS can have min and max protection rules
			// :: prev_info.max_protection
			mr = r_debug_map_new (buf, prev_address, prev_address+prev_size, prev_info.protection, 0);
			if (mr == NULL) {
				eprintf ("Cannot create r_debug_map_new\n");
				break;
			}
			r_list_append (list, mr);
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

static RList *r_debug_native_map_get(RDebug *dbg) {
	RList *list = NULL;
#if __APPLE__
	list = darwin_dbg_maps (dbg);
#elif __WINDOWS__
	list = w32_dbg_maps (); // TODO: moar?
#else
#if __sun
	char path[1024];
	/* TODO: On solaris parse /proc/%d/map */
	sprintf (path, "pmap %d > /dev/stderr", ps.tid);
	system (path);
#else
	RDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024];
	char region[100], region2[100], perms[5], null[16];
	FILE *fd;
	if (dbg->pid == -1) {
		eprintf ("r_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}

#if __FreeBSD__
	sprintf (path, "/proc/%d/map", dbg->pid);
#else
	sprintf (path, "/proc/%d/maps", dbg->pid);
#endif
	fd = fopen (path, "r");
	if (!fd) {
		perror ("debug_init_maps: /proc");
		return NULL;
	}

	list = r_list_new ();

	while (!feof (fd)) {
		line[0]='\0';
		fgets (line, 1023, fd);
		if (line[0]=='\0')
			break;
		path[0]='\0';
		line[strlen (line)-1]='\0';
#if __FreeBSD__
		// 0x8070000 0x8072000 2 0 0xc1fde948 rw- 1 0 0x2180 COW NC vnode /usr/bin/gcc
		sscanf (line, "%s %s %d %d 0x%s %3s %d %d",
			&region[2], &region2[2], &ign, &ign,
			unkstr, perms, &ign, &ign);
		pos_c = strchr (line, '/');
		if (pos_c) strcpy (path, pos_c);
		else path[0]='\0';
#else
		sscanf (line, "%s %s %s %s %s %s",
			&region[2], perms,  null, null, null, path);

		pos_c = strchr (&region[2], '-');
		if (!pos_c)
			continue;

		pos_c[-1] = (char)'0';
		pos_c[ 0] = (char)'x';
		strcpy (region2, pos_c-1);
#endif // __FreeBSD__
		region[0] = region2[0] = '0';
		region[1] = region2[1] = 'x';

		if (!*path)
			sprintf (path, "unk%d", unk++);

		perm = 0;
		for(i = 0; perms[i] && i < 4; i++)
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
#if __i386__
/* TODO: Can I use this as in a coroutine? */
static RList *r_debug_native_frames(RDebug *dbg) {
	RRegItem *ri;
	RReg *reg = dbg->reg;
	ut32 i, _esp, esp, ebp2;
	RList *list = r_list_new ();
	RIOBind *bio = &dbg->iob;
	ut8 buf[4];

	list->free = free;
	ri = r_reg_get (reg, "esp", R_REG_TYPE_GPR);
	if (ri != NULL) {
		_esp = r_reg_get_value (reg, ri);
		// TODO: implement [stack] map uptrace method too
		esp = _esp;
		for (i=0; i<MAXBT; i++) {
			bio->read_at (bio->io, esp, (void *)&ebp2, 4);
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
	}
	return list;
}
#elif __x86_64__
// XXX: Do this work correctly?
static RList *r_debug_native_frames(RDebug *dbg) {
	int i;
	ut8 buf[4];
	ut64 ptr, ebp2;
	ut64 _rip, _rsp, _rbp;
	RList *list;
	RReg *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;

	_rip = r_reg_get_value (reg, r_reg_get (reg, "rip", R_REG_TYPE_GPR));
	_rsp = r_reg_get_value (reg, r_reg_get (reg, "rsp", R_REG_TYPE_GPR));
	_rbp = r_reg_get_value (reg, r_reg_get (reg, "rbp", R_REG_TYPE_GPR));

	list = r_list_new ();
	list->free = free;
	bio->read_at (bio->io, _rip, (ut8*)&buf, 4);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Plugin before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp (buf, "\x55\x89\xe5", 3) || !memcmp (buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at (bio->io, _rsp, (ut8*)&ptr, 4) != 4) {
			eprintf ("read error at 0x%08"PFMT64x"\n", _rsp);
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
		RDebugFrame *frame;
		bio->read_at (bio->io, _rbp, (ut8*)&ebp2, 4);
		bio->read_at (bio->io, _rbp+4, (ut8*)&ptr, 4);
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
#else
#warning Backtrace frames not implemented for this platform
static RList *r_debug_native_frames(RDebug *dbg) {
       return NULL;
}
#endif

// TODO: implement own-defined signals
static int r_debug_native_kill(RDebug *dbg, boolt thread, int sig) {
#if __WINDOWS__
	// TODO: implement thread support signaling here
	HANDLE hProcess; // XXX
#if 0
    static uint WM_CLOSE = 0x10;
    static bool CloseWindow(IntPtr hWnd) {
	hWnd = FindWindowByCaption (0, "explorer");
        SendMessage(hWnd, WM_CLOSE, NULL, NULL);
	CloseWindow(hWnd);
        return true;
    }
#endif
	TerminateProcess (hProcess, 1);
	return R_FALSE;
#else
	int ret = R_FALSE;
	if (thread) {
#if 0
// XXX this is linux>2.5 specific..ugly
		if (dbg->tid>0 && (ret = tgkill (dbg->pid, dbg->tid, sig))) {
			if (ret != -1)
				ret = R_TRUE;
		}
#endif
	} else {
		if (dbg->pid>0 && (ret = kill (dbg->pid, sig))) {
			if (ret != -1)
				ret = R_TRUE;
		}
	}
	return ret;
#endif
}

static int r_debug_native_init(RDebug *dbg) {
#if __WINDOWS__
	return w32_dbg_init ();
#else
	return R_TRUE;
#endif
}

#if __i386__ || __x86_64__
int drx_add(RDebug *dbg, ut64 addr, int rwx) {
	// TODO
	return R_FALSE;
}

int drx_del(RDebug *dbg, ut64 addr, int rwx) {
	// TODO
	return R_FALSE;
}
#endif

static int r_debug_native_bp(void *user, int add, ut64 addr, int hw, int rwx) {
#if __i386__ || __x86_64__
	RDebug *dbg = user;
	if (hw) {
		if (add) return drx_add (dbg, addr, rwx);
		return drx_del (dbg, addr, rwx);
	}
#endif
	return R_FALSE;
}

struct r_debug_plugin_t r_debug_plugin_native = {
	.name = "native",
#if __i386__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_X86,
#elif __x86_64__
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.arch = R_ASM_ARCH_X86,
#elif __arm__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_ARM,
#elif __mips__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_MIPS,
#elif __powerpc__
	.bits = R_SYS_BITS_32,
	.arch = R_ASM_ARCH_PPC,
#else
#warning Unsupported architecture
#endif
	.init = &r_debug_native_init,
	.step = &r_debug_native_step,
	.cont = &r_debug_native_continue,
	.contsc = &r_debug_native_continue_syscall,
	.attach = &r_debug_native_attach,
	.detach = &r_debug_native_detach,
	.pids = &r_debug_native_pids,
	.threads = &r_debug_native_threads,
	.wait = &r_debug_native_wait,
	.kill = &r_debug_native_kill,
	.frames = &r_debug_native_frames,
	.reg_profile = (void *)&r_debug_native_reg_profile,
	.reg_read = &r_debug_native_reg_read,
	.reg_write = (void *)&r_debug_native_reg_write,
	.map_get = (void *)&r_debug_native_map_get,
	.breakpoint = r_debug_native_bp,
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
