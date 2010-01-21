/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

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
#elif __linux__
#include <sys/user.h>
#include <limits.h>
#define R_DEBUG_REG_T struct user_regs_struct
#else
#warning Unsupported debugging platform
#endif

#if __WINDOWS__
struct r_debug_handle_t r_debug_plugin_ptrace = {
	.name = "ptrace",
};
#else

#if DEBUGGER

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

static int r_debug_ptrace_step(int pid)
{
	int ret;
	ut32 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	ret = ptrace (PTRACE_SINGLESTEP, pid, addr, 0); //addr, data);
	if (ret == -1)
		perror("ptrace-singlestep");
	return R_TRUE;
}

static int r_debug_ptrace_attach(int pid)
{
	void *addr = 0;
	void *data = 0;
	int ret = ptrace (PTRACE_ATTACH, pid, addr, data);
	return (ret != -1)?R_TRUE:R_FALSE;
}

static int r_debug_ptrace_detach(int pid)
{
	void *addr = 0;
	void *data = 0;
	return ptrace (PTRACE_DETACH, pid, addr, data);
}

static int r_debug_ptrace_continue(int pid, int sig)
{
	void *addr = NULL; // eip for BSD
	void *data = NULL;
	if (sig != -1)
		data = (void*)(size_t)sig;
	return ptrace (PTRACE_CONT, pid, addr, data);
}

static int r_debug_ptrace_wait(int pid)
{
	int ret, status = -1;
	//printf("prewait\n");
	ret = waitpid(pid, &status, 0);
	//printf("status=%d (return=%d)\n", status, ret);
	return status;
}

// TODO: why strdup here?
static const char *r_debug_ptrace_reg_profile()
{
#if __i386__
	return strdup(
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
	"\n"
	"# base address is 448bit\n"
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
#warning linux-x86-64 register profile is really incomplete
	return strdup (
	"# no profile defined for x86-64\n"
	"gpr	rbx	.32	0	0\n"
	"gpr	rcx	.32	0	8\n"
	"gpr	rdx	.32	0	16\n"
	"gpr	rsi	.32	0	24\n"
	"gpr	rdi	.32	0	32\n"
	"gpr	rip	.32	0	32\n"
	);
#endif
}

// TODO: what about float and hardware regs here ???
// TODO: add flag for type
static int r_debug_ptrace_reg_read(struct r_debug_t *dbg, int type, ut8 *buf, int size)
{
	int ret; 
	int pid = dbg->pid;
	if (type == R_REG_TYPE_GPR) {
// XXX this must be defined somewhere else
#if __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
		R_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
#if __NetBSD__ || __FreeBSD__ || __OpenBSD__
		ret = ptrace (PTRACE_GETREGS, pid, &regs, sizeof (regs));
#elif __linux__ && __powerpc__
		ret = ptrace (PTRACE_GETREGS, pid, &regs, NULL);
#else __sun
		ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
#endif
		if (sizeof(regs) < size)
			size = sizeof(regs);
		if (ret != 0)
			return R_FALSE;
		memcpy(buf, &regs, size);
		return sizeof(regs);
		//r_reg_set_bytes(reg, &regs, sizeof(struct user_regs));
#else
#warning dbg-ptrace not supported for this platform
	return 0;
#endif
	}

	return 0;
}

static int r_debug_ptrace_reg_write(int pid, int type, const ut8* buf, int size) {
	int ret;
	// XXX use switch or so
	if (type == R_REG_TYPE_GPR) {
#if __linux__ || __sun || __NetBSD__ || __FreeBSD__ || __OpenBSD__
		ret = ptrace(PTRACE_SETREGS, pid, 0, buf);
		if (sizeof(struct user_regs_struct) < size)
			size = sizeof(struct user_regs_struct);
		if (ret != 0)
			return R_FALSE;
		return R_TRUE;
#else
		#warning r_debug_ptrace_reg_write not implemented
#endif
	} else eprintf("TODO: reg_write_non-gpr (%d)\n", type);
	return R_FALSE;
}

// TODO: deprecate???
#if 0
static int r_debug_ptrace_bp_write(int pid, ut64 addr, int size, int hw, int rwx) {
	if (hw) {
		/* implement DRx register handling here */
		return R_TRUE;
	}
	return R_FALSE;
}

/* TODO: rethink */
static int r_debug_ptrace_bp_read(int pid, ut64 addr, int hw, int rwx)
{
	return R_TRUE;
}
#endif

static int r_debug_get_arch()
{
#if __i386__
	return R_ASM_ARCH_X86;
#elif __x86_64__
	return R_ASM_ARCH_X86_64;
#elif __powerpc__
	return R_ASM_ARCH_POWERPC;
#elif __mips__
	return R_ASM_ARCH_MIPS;
#elif __arm__
	return R_ASM_ARCH_ARM;
#endif
}

#if 0
static int r_debug_ptrace_import(struct r_debug_handle_t *from)
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
struct r_debug_handle_t r_debug_plugin_ptrace = {
	.name = "ptrace",
	.archs = (const char **)archlist,
	.step = &r_debug_ptrace_step,
	.cont = &r_debug_ptrace_continue,
	.attach = &r_debug_ptrace_attach,
	.detach = &r_debug_ptrace_detach,
	.wait = &r_debug_ptrace_wait,
	.get_arch = &r_debug_get_arch,
	.reg_profile = (void *)&r_debug_ptrace_reg_profile,
	.reg_read = &r_debug_ptrace_reg_read,
	.reg_write = (void *)&r_debug_ptrace_reg_write,
	//.bp_read = &r_debug_ptrace_bp_read,
	//.bp_write = &r_debug_ptrace_bp_write,
};

#endif
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_ptrace
};
#endif
