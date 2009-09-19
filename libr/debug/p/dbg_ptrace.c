/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_userconf.h>

#if DEBUGGER

#include <r_debug.h>
#include <r_asm.h>
#include <r_lib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

static int r_debug_ptrace_step(int pid)
{
	int ret;
	ut32 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	ret = ptrace(PTRACE_SINGLESTEP, pid, addr, 0); //addr, data);
	if (ret == -1)
		perror("ptrace-singlestep");
	return R_TRUE;
}

static int r_debug_ptrace_attach(int pid)
{
	void *addr = 0;
	void *data = 0;
	int ret = ptrace(PTRACE_ATTACH, pid, addr, data);
	return (ret != -1)?R_TRUE:R_FALSE;
}

static int r_debug_ptrace_detach(int pid)
{
	void *addr = 0;
	void *data = 0;
	return ptrace(PTRACE_DETACH, pid, addr, data);
}

static int r_debug_ptrace_continue(int pid)
{
	void *addr = 0;
	void *data = 0;
	return ptrace(PTRACE_CONT, pid, addr, data);
}

static int r_debug_ptrace_wait(int pid)
{
	int ret, status = -1;
	//printf("prewait\n");
	ret = waitpid(pid, &status, 0);
	//printf("status=%d (return=%d)\n", status, ret);
	return status;
}

// TODO: what about float and hardware regs here ???
struct r_regset_t* r_debug_ptrace_reg_read(int pid)
{
	struct r_regset_t *r = NULL;
// XXX this must be defined somewhere else
#if __linux__
#include <sys/user.h>
#include <limits.h>
	struct user_regs_struct regs;
	memset(&regs,0, sizeof(regs));
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
#if 0
#if __WORDSIZE == 64
	r = r_regset_new(17);
	r_regset_set(r, 0, "rax", regs.rax);
	r_regset_set(r, 1, "rbx", regs.rbx);
	r_regset_set(r, 2, "rcx", regs.rcx);
	r_regset_set(r, 3, "rdx", regs.rdx);
	r_regset_set(r, 4, "rsi", regs.rsi);
	r_regset_set(r, 5, "rdi", regs.rdi);
	r_regset_set(r, 6, "rsp", regs.rsp);
	r_regset_set(r, 7, "rbp", regs.rbp);
	r_regset_set(r, 8, "rip", regs.rip);
	r_regset_set(r, 9, "r8", regs.r8);
	r_regset_set(r, 10, "r9", regs.r9);
	r_regset_set(r, 11, "r10", regs.r10);
	r_regset_set(r, 12, "r11", regs.r11);
	r_regset_set(r, 13, "r12", regs.r12);
	r_regset_set(r, 14, "r13", regs.r13);
	r_regset_set(r, 15, "r14", regs.r14);
	r_regset_set(r, 16, "r15", regs.r15);
#else
	/* TODO: use enum for 0, 1, 2... ? */
	/* TODO: missing eflags here */
	r = r_regset_new(9);
	r_regset_set(r, 0, "eax", (ut64)(ut32)regs.eax);
	r_regset_set(r, 1, "ebx", (ut64)(ut32)regs.ebx);
	r_regset_set(r, 2, "ecx", (ut64)(ut32)regs.ecx);
	r_regset_set(r, 3, "edx", (ut64)(ut32)regs.edx);
	r_regset_set(r, 4, "esi", (ut64)(ut32)regs.esi);
	r_regset_set(r, 5, "edi", (ut64)(ut32)regs.edi);
	r_regset_set(r, 6, "esp", (ut64)(ut32)regs.esp);
	r_regset_set(r, 7, "ebp", (ut64)(ut32)regs.ebp);
	r_regset_set(r, 8, "eip", (ut64)(ut32)regs.eip);
#endif
#endif /* linux */
#endif
	return r;
}

static int r_debug_ptrace_reg_write(int pid, struct r_regset_t *regs)
{
	/* TODO */
	return 0;
}

// TODO: deprecate???
static int r_debug_ptrace_bp_write(int pid, ut64 addr, int size, int hw, int rwx)
{
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

static int r_debug_get_arch()
{
	return R_ASM_ARCH_X86;
#if 0
#if __WORDSIZE == 64
	return R_ASM_ARCH_X86_64;
#else
	return R_ASM_ARCH_X86;
#endif
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

struct r_debug_handle_t r_debug_plugin_ptrace = {
	.name = "dbg.ptrace",
#if __WORDSIZE == 64
	.archs = { "x86-64", 0 },
#else
	.archs = { "x86", "x86-32", 0 },
#endif
	.step = &r_debug_ptrace_step,
	.cont = &r_debug_ptrace_continue,
	.attach = &r_debug_ptrace_attach,
	.detach = &r_debug_ptrace_detach,
	.wait = &r_debug_ptrace_wait,
	.get_arch = &r_debug_get_arch,
	//.bp_write = &r_debug_ptrace_bp_write,
	.reg_read = &r_debug_ptrace_reg_read,
	.reg_write = &r_debug_ptrace_reg_write,
	//.bp_read = &r_debug_ptrace_bp_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_ptrace
};
#endif

#endif
