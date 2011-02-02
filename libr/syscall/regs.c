#include <r_syscall.h>

static struct r_syscall_regs_t fastcall[R_SYSCALL_ARGS] = {
	{ NULL },
	{ "a0", NULL },
	{ "a0", "a1", NULL },
	{ "a0", "a1", "a2", NULL },
	{ "a0", "a1", "a2", "a3", NULL },
	NULL
};

static struct r_syscall_regs_t fastcall [R_SYSCALL_ARGS] = {
	{ NULL },
	{ "eax", NULL },
	{ "eax", "ebx", NULL },
	{ "eax", "ebx", "ecx", NULL },
	{ "eax", "ebx", "ecx", "edx", NULL },
	NULL
};

/* return fastcall register argument 'idx' for a syscall with 'num' args */
R_API const char *r_syscall_reg(RSyscall *s, int idx, int num) {
	struct r_syscall_regs_t *regs;
	const char *ret = NULL;
	if (s && s->regs)
		regs = *a->cur->fastcall;
	if (regs && idx<=num && num<R_SYSCALL_ARGS)
		ret = regs[num].arg[idx];
	return ret;
}
