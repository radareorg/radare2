/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <signal.h>

#define DEBUGGER 1
#define MAXBT 128

#if __WINDOWS__
#include <windows.h>
#define R_DEBUG_REG_T CONTEXT

#elif __OpenBSD__ || __NetBSD__ || __FreeBSD__
#define R_DEBUG_REG_T struct reg

#elif __APPLE__

#define MACH_ERROR_STRING(ret) \
	(mach_error_string (ret) ? mach_error_string (ret) : "(unknown)")

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#if __POWERPC__
#include <mach/ppc/_types.h>
#include <mach/ppc/thread_status.h>
#define R_DEBUG_REG_T ppc_thread_state_t
#define R_DEBUG_STATE_T PPC_THREAD_STATE
#elif __arm
#include <mach/arm/thread_status.h>
#define R_DEBUG_REG_T arm_thread_state_t
#define R_DEBUG_STATE_T ARM_THREAD_STATE
#else
#include <mach/i386/thread_status.h>
#include <sys/ucontext.h>
#define R_DEBUG_REG_T _STRUCT_X86_THREAD_STATE32
#include <mach/i386/_structs.h>
#define R_DEBUG_STATE_T i386_THREAD_STATE
#endif

#elif __sun
#define R_DEBUG_REG_T gregset_t
#undef DEBUGGER
#define DEBUGGER 0
#warning No debugger support for SunOS yet

#elif __linux__
#include <sys/user.h>
#include <limits.h>
# if __i386__ || __x86_64__
# define R_DEBUG_REG_T struct user_regs_struct
# elif __arm__
# define R_DEBUG_REG_T struct user_regs
# endif
#else // OS

#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // ARCH

#if DEBUGGER
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#if __APPLE__
// TODO: move into native/
task_t pid_to_task(int pid) {
	static task_t old_pid  = -1;
	static task_t old_task = -1;
	task_t task = 0;
	int err;

	/* xlr8! */
	if (old_task!= -1) //old_pid != -1 && old_pid == pid)
		return old_task;

	err = task_for_pid(mach_task_self(), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID(task)) {
		eprintf ("Failed to get task %d for pid %d.\n", (int)task, (int)pid);
		eprintf ("Reason: 0x%x: %s\n", err, MACH_ERROR_STRING(err));
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
static void debug_arch_x86_trap_set(int pid, int foo) {
#if __i386__ || __x86_64__
        R_DEBUG_REG_T regs;
        debug_getregs (pid_to_task (pid), &regs);
        printf("trap flag: %d\n", (regs.__eflags&0x100));
        if (foo) regs.__eflags |= EFLAGS_TRAP_FLAG;
        else regs.__eflags &= ~EFLAGS_TRAP_FLAG;
        debug_setregs (pid_to_task (pid), &regs);
#endif
}
#endif // __APPLE__

static int r_debug_native_step(int pid) {
	int ret = R_FALSE;
	//R_DEBUG_REG_T regs;

#if __APPLE__
	debug_arch_x86_trap_set (pid, 1);
	//eprintf ("stepping from pc = %08x\n", (ut32)get_offset("eip"));
	//ret = ptrace (PT_STEP, ps.tid, (caddr_t)get_offset("eip"), SIGSTOP);
	ret = ptrace (PT_STEP, pid, (caddr_t)1, SIGTRAP); //SIGINT);
	if (ret != 0) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING(ret));
		/* DO NOT WAIT FOR EVENTS !!! */
		ret = R_FALSE;
	} else ret = R_TRUE;
#else // __APPLE__
	ut32 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	ret = ptrace (PTRACE_SINGLESTEP, pid, addr, 0); //addr, data);
	if (ret == -1) {
		perror ("native-singlestep");
		ret = R_FALSE;
	} else ret = R_TRUE;
#endif // __APPLE_
	return ret;
}

static int r_debug_native_attach(int pid) {
	void *addr = 0;
	void *data = 0;
#if __APPLE__
	int ret = ptrace (PT_ATTACH, pid, addr, data);
#else
	int ret = ptrace (PTRACE_ATTACH, pid, addr, data);
#endif
	return (ret != -1)?R_TRUE:R_FALSE;
}

static int r_debug_native_detach(int pid) {
	void *addr = 0;
	void *data = 0;
#if __APPLE__
	return ptrace (PT_DETACH, pid, addr, data);
#else
	return ptrace (PTRACE_DETACH, pid, addr, data);
#endif
}

static int r_debug_native_continue(int pid, int sig) {
	void *data = NULL;
	if (sig != -1)
		data = (void*)(size_t)sig;
#if __APPLE__
        eprintf ("debug_contp: program is now running...\n");
 
	/* XXX */
	/* only stopped with ptrace the first time */
	//ptrace(PT_CONTINUE, pid, 0, 0);
	ptrace (PT_DETACH, pid, 0, 0);
	#if 0
	task_resume(inferior_task); // ???
	thread_resume(inferior_threads[0]);
	#endif
        return 0;
#else
	void *addr = NULL; // eip for BSD
	return ptrace (PTRACE_CONT, pid, addr, data);
#endif
}

static int r_debug_native_wait(int pid) {
	int ret, status = -1;
	//printf ("prewait\n");
	ret = waitpid (pid, &status, 0);
	//printf ("status=%d (return=%d)\n", status, ret);
	return status;
}

// TODO: why strdup here?
static const char *r_debug_native_reg_profile() {
#if __POWERPC__ && __APPLE__
	return strdup(
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
	return strdup(
	"=pc	eip\n"
	"=sp	esp\n"
	"=bp	ebp\n"
	"=a0	eax\n"
	"=a1	ebx\n"
	"=a2	ecx\n"
	"=a3	edx\n"
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
	"gpr	eflags	.32	56	0\n"
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
	"flg	eflags	.64	144	0\n"
	"gpr	rsp	.64	152	0\n"
	"seg	ss	.64	160	0\n"
	"seg	fs_base	.64	168	0\n"
	"seg	gs_base	.64	176	0\n"
	"seg	ds	.64	184	0\n"
	"seg	es	.64	192	0\n"
	"seg	fs	.64	200	0\n"
	"seg	gs	.64	208	0\n"
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
#endif
	return NULL;
}

// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static int r_debug_native_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	int ret; 
	int pid = dbg->pid;
// XXX this must be defined somewhere else
#if __APPLE__
	thread_array_t inferior_threads = NULL;
	unsigned int inferior_thread_count = 0;
	R_DEBUG_REG_T *regs = (R_DEBUG_REG_T *)buf;
        unsigned int gp_count = sizeof (R_DEBUG_REG_T);

        //thread_act_port_array_t thread_list;
        //mach_msg_type_number_t thread_count;

        ret = task_threads (pid_to_task (pid), &inferior_threads, &inferior_thread_count);
        if (ret != KERN_SUCCESS) {
                eprintf ("debug_getregs\n");
                return R_FALSE;
        }

        if (inferior_thread_count>0) {
                /* TODO: allow to choose the thread */
                if ((ret = thread_get_state (inferior_threads[0], R_DEBUG_STATE_T,
				(thread_state_t) regs, &gp_count)) != KERN_SUCCESS) {
                        eprintf ("debug_getregs: Failed to get thread %d %d.error (%x). (%s)\n",
				(int)pid, pid_to_task (pid), (int)ret, MACH_ERROR_STRING (ret));
                        perror ("thread_get_state");
                        return R_FALSE;
                }
        } else eprintf ("There are no threads!\n");
        return R_TRUE; //gp_count;

#elif __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
	switch (type) {
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
			size = sizeof(regs);
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

static int r_debug_native_reg_write(int pid, int type, const ut8* buf, int size) {
	// XXX use switch or so
	if (type == R_REG_TYPE_GPR) {
#if __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
		int ret = ptrace (PTRACE_SETREGS, pid, 0, buf);
		if (sizeof (R_DEBUG_REG_T) < size)
			size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? R_FALSE: R_TRUE;
#else
		#warning r_debug_native_reg_write not implemented
#endif
	} else eprintf("TODO: reg_write_non-gpr (%d)\n", type);
	return R_FALSE;
}

static RList *r_debug_native_map_get(struct r_debug_t *dbg) {
	char path[1024];
	RList *list = NULL;
#if __sun
	/* TODO: On solaris parse /proc/%d/map */
	sprintf (path, "pmap %d > /dev/stderr", ps.tid);
	system (path);
#else
	RDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char region[100], region2[100], perms[5], null[16];
	char line[1024];
	FILE *fd;
#if __FreeBSD__
	sprintf (path, "/proc/%d/map", dbg->pid);
#else
	sprintf (path, "/proc/%d/maps", dbg->pid);
#endif
	fd = fopen (path, "r");
	if (!fd) {
		perror ("debug_init_maps");
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
	RRegister *reg = dbg->reg;
	ut32 i, _esp, esp, ebp2;
	ut8 buf[4];
	RList *list = r_list_new ();
	RIOBind *bio = &dbg->iob;

	list->free = free;
	_esp = r_reg_get_value (reg, r_reg_get (reg, "esp", R_REG_TYPE_GPR));
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
	RRegister *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;

	_rip = r_reg_get_value (reg, r_reg_get (reg, "rip", R_REG_TYPE_GPR));
	_rsp = r_reg_get_value (reg, r_reg_get (reg, "rsp", R_REG_TYPE_GPR));
	_rbp = r_reg_get_value (reg, r_reg_get (reg, "rbp", R_REG_TYPE_GPR));

	list = r_list_new ();
	list->free = free;
	bio->read_at (bio->io, _rip, &buf, 4);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Handle before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp (buf, "\x55\x89\xe5", 3) || !memcmp (buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at (bio->io, _rsp, &ptr, 4) != 4) {
			eprintf ("read error at 0x%08llx\n", _rsp);
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
		bio->read_at (bio->io, _rbp, &ebp2, 4);
		bio->read_at (bio->io, _rbp+4, &ptr, 4);
		if (ptr == 0x0 || _rbp == 0x0)
			break;

		RDebugFrame *frame = R_NEW (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);

		_rbp = ebp2;
	}
	return list;
}
#else
#warning Backtrace frames not implemented for this platform
#endif

static int r_debug_native_kill(struct r_debug_t *dbg, int sig) {
#if __WINDOWS__
	TerminateProcess (WIN32_PI(hProcess), 1);
	return R_FALSE;
#else
	int ret = kill (dbg->pid, sig);
	if (ret == -1)
		return R_FALSE;
	return R_TRUE;
#endif
}

struct r_debug_handle_t r_debug_plugin_native = {
	.name = "native",
#if __i386__
	.bits = R_DBG_BIT_32,
	.arch = R_ASM_ARCH_X86,
#elif __x86_64__
	.bits = R_DBG_BIT_32 | R_DBG_BIT_64,
	.arch = R_ASM_ARCH_X86,
#elif __arm__
	.bits = R_DBG_BIT_32,
	.arch = R_ASM_ARCH_ARM,
#elif __mips__
	.bits = R_DBG_BIT_32,
	.arch = R_ASM_ARCH_MIPS,
#elif __powerpc__
	.bits = R_DBG_BIT_32,
	.arch = R_ASM_ARCH_PPC,
#else
#warning food
#endif
	.step = &r_debug_native_step,
	.cont = &r_debug_native_continue,
	.attach = &r_debug_native_attach,
	.detach = &r_debug_native_detach,
	.wait = &r_debug_native_wait,
	.kill = &r_debug_native_kill,
	.frames = &r_debug_native_frames,
	.reg_profile = (void *)&r_debug_native_reg_profile,
	.reg_read = &r_debug_native_reg_read,
	.reg_write = (void *)&r_debug_native_reg_write,
	.map_get = (void *)&r_debug_native_map_get,
	//.bp_read = &r_debug_native_bp_read,
	//.bp_write = &r_debug_native_bp_write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_native
};
#endif // CORELIB

//#endif
#else // DEBUGGER
struct r_debug_handle_t r_debug_plugin_native = {
	.name = "native",
};

#endif // DEBUGGER
