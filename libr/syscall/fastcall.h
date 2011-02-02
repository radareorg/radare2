/* radare 2010-2011 GPL -- pancake <youterm.com> */

#include <r_syscall.h>

static struct r_syscall_regs_t fastcall_arm [R_SYSCALL_ARGS] = {
	{{ "r0", NULL }},
	{{ "r0", "r1", NULL }},
	{{ "r0", "r1", "r2", NULL }},
	{{ "r0", "r1", "r2", "r3", NULL }},
	{{ NULL }}
};

static struct r_syscall_regs_t fastcall_mips [R_SYSCALL_ARGS] = {
	{{ "a0", NULL }},
	{{ "a0", "a1", NULL }},
	{{ "a0", "a1", "a2", NULL }},
	{{ "a0", "a1", "a2", "a3", NULL }},
	{{ NULL }}
};

// TODO: add ppc and ppc64 regs here
// TODO: add support for 64bit syscalls here
static struct r_syscall_regs_t fastcall_x86 [R_SYSCALL_ARGS] = {
	{{ "eax", NULL }},
	{{ "eax", "ebx", NULL }},
	{{ "eax", "ebx", "ecx", NULL }},
	{{ "eax", "ebx", "ecx", "edx", NULL }},
	{{ NULL }}
};
