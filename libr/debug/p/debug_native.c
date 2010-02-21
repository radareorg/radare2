/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_userconf.h>
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>

#if __WINDOWS__
#include <windows.h>
#define R_DEBUG_REG_T CONTEXT

#elif __OpenBSD__ || __NetBSD__ || __FreeBSD__
#define R_DEBUG_REG_T struct reg

#elif __sun
#define R_DEBUG_REG_T gregset_t
#undef DEBUGGER
#define DEBUGGER 0
#warning No debugger support for OSX yet

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
#else
#warning Unsupported debugging platform
#endif

#if __WINDOWS__ || __sun || __APPLE__
struct r_debug_handle_t r_debug_plugin_native = {
	.name = "native",
};
#else

#if DEBUGGER

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

static int r_debug_native_step(int pid)
{
	int ret;
	ut32 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	ret = ptrace (PTRACE_SINGLESTEP, pid, addr, 0); //addr, data);
	if (ret == -1)
		perror("native-singlestep");
	return R_TRUE;
}

static int r_debug_native_attach(int pid)
{
	void *addr = 0;
	void *data = 0;
	int ret = ptrace (PTRACE_ATTACH, pid, addr, data);
	return (ret != -1)?R_TRUE:R_FALSE;
}

static int r_debug_native_detach(int pid)
{
	void *addr = 0;
	void *data = 0;
	return ptrace (PTRACE_DETACH, pid, addr, data);
}

static int r_debug_native_continue(int pid, int sig)
{
	void *addr = NULL; // eip for BSD
	void *data = NULL;
	if (sig != -1)
		data = (void*)(size_t)sig;
	return ptrace (PTRACE_CONT, pid, addr, data);
}

static int r_debug_native_wait(int pid)
{
	int ret, status = -1;
	//printf("prewait\n");
	ret = waitpid(pid, &status, 0);
	//printf("status=%d (return=%d)\n", status, ret);
	return status;
}

// TODO: why strdup here?
static const char *r_debug_native_reg_profile()
{
#if __i386__
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
#warning linux-x64 reg profile is incomplete
	return strdup (
	"=pc	rip\n"
	"=sp	rsp\n"
	"=bp	rbp\n"
	"=a0	rax\n"
	"=a1	rbx\n"
	"=a2	rcx\n"
	"=a3	rdx\n"
	"# no profile defined for x86-64\n"
	"gpr	rbx	.32	0	0\n"
	"gpr	rcx	.32	8	0\n"
	"gpr	rdx	.32	16	0\n"
	"gpr	rsi	.32	24	0\n"
	"gpr	rdi	.32	32	0\n"
	"gpr	rip	.32	40	0\n"
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
static int r_debug_native_reg_read(struct r_debug_t *dbg, int type, ut8 *buf, int size)
{
	int ret; 
	int pid = dbg->pid;
// XXX this must be defined somewhere else
#if __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
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
		//r_reg_set_bytes(reg, &regs, sizeof(struct user_regs));
	}
#else
#warning dbg-native not supported for this platform
#endif
	return 0;
}

static int r_debug_native_reg_write(int pid, int type, const ut8* buf, int size) {
	int ret;
	// XXX use switch or so
	if (type == R_REG_TYPE_GPR) {
#if __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
		ret = ptrace (PTRACE_SETREGS, pid, 0, buf);
		if (sizeof (R_DEBUG_REG_T) < size)
			size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? R_FALSE: R_TRUE;
#else
		#warning r_debug_native_reg_write not implemented
#endif
	} else eprintf("TODO: reg_write_non-gpr (%d)\n", type);
	return R_FALSE;
}

static RList *r_debug_native_map_get(struct r_debug_t *dbg)
{
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
	if(!fd) {
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
			&region[2], &region2[2], &ign, &ign, unkstr, perms, &ign, &ign);
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
	fclose(fd);
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
static int r_debug_native_bp_read(int pid, ut64 addr, int hw, int rwx)
{
	return R_TRUE;
}
#endif

static int r_debug_get_arch()
{
#if __i386__ || __x86_64__
	return R_ASM_ARCH_X86;
#elif __powerpc__
	return R_ASM_ARCH_POWERPC;
#elif __mips__
	return R_ASM_ARCH_MIPS;
#elif __arm__
	return R_ASM_ARCH_ARM;
#endif
}

#if 0
static int r_debug_native_import(struct r_debug_handle_t *from)
{
	//int pid = from->export(R_DEBUG_GET_PID);
	//int maps = from->export(R_DEBUG_GET_MAPS);
	return R_FALSE;
}
#endif
#if __i386__
const char *archlist[3] = { "x86", "x86-32", 0 };
#elif __x86_64__
const char *archlist[4] = { "x86", "x86-32", "x86-64", 0 };
#elif __powerpc__
const char *archlist[3] = { "powerpc", 0 };
#elif __mips__
const char *archlist[3] = { "mips", 0 };
#elif __arm__
const char *archlist[3] = { "arm", 0 };
#endif

// TODO: think on a way to define the program counter register name
struct r_debug_handle_t r_debug_plugin_native = {
	.name = "native",
	.archs = (const char **)archlist,
	.step = &r_debug_native_step,
	.cont = &r_debug_native_continue,
	.attach = &r_debug_native_attach,
	.detach = &r_debug_native_detach,
	.wait = &r_debug_native_wait,
	.get_arch = &r_debug_get_arch,
	.reg_profile = (void *)&r_debug_native_reg_profile,
	.reg_read = &r_debug_native_reg_read,
	.reg_write = (void *)&r_debug_native_reg_write,
	.map_get = (void *)&r_debug_native_map_get,
	//.bp_read = &r_debug_native_bp_read,
	//.bp_write = &r_debug_native_bp_write,
};

#endif
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_native
};
#endif
