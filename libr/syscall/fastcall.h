/* radare 2010-2013 GPL -- pancake */

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

static struct r_syscall_regs_t fastcall_x86_32 [R_SYSCALL_ARGS] = {
	{{ "eax", NULL }},
	{{ "eax", "ebx", NULL }},
	{{ "eax", "ebx", "ecx", NULL }},
	{{ "eax", "ebx", "ecx", "edx", NULL }},
	{{ NULL }}
};

// TODO: x86-64-microsoft RCX, RDX, R8, R9 
static struct r_syscall_regs_t fastcall_x86_64 [R_SYSCALL_ARGS] = {
	{{ "rdi", NULL }},
	{{ "rdi", "rsi", NULL }},
	{{ "rdi", "rsi", "rdx", NULL }},
	{{ "rdi", "rsi", "rdx", "rdx", NULL }},
	{{ "rdi", "rsi", "rdx", "rdx", "r8", NULL }},
	{{ "rdi", "rsi", "rdx", "rdx", "r8", "r9", NULL }},
	{{ NULL }}
};

static struct r_syscall_regs_t fastcall_x86_8 [R_SYSCALL_ARGS] = {
	{{ "ax", NULL }},
	{{ "ax", "dx", NULL }},
	{{ "ax", "dx", "bx", NULL }},
	{{ "ax", "dx", "bx", "cx", NULL }},
	{{ NULL }}
};

static struct r_syscall_regs_t fastcall_sh [R_SYSCALL_ARGS] = {
	{{ "r4", NULL }},
	{{ "r4", "r5", NULL }},
	{{ "r4", "r5", "r6", NULL }},
	{{ "r4", "r5", "r6", "r7", NULL }},
	{{ NULL }}
};
