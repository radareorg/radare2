/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>
#include <sys/ptrace.h>

int r_debug_ptrace_step(int pid)
{
	u32 addr;
	u32 data;
	return ptrace(PTRACE_SINGLESTEP, pid, addr, data);
}

int r_debug_ptrace_attach(int pid)
{
	u32 addr;
	u32 data;
	return ptrace(PTRACE_ATTACH, pid, addr, data);
}

int r_debug_ptrace_detach(int pid)
{
	u32 addr;
	u32 data;
	return ptrace(PTRACE_DETACH, pid, addr, data);
}

int r_debug_ptrace_continue(int pid)
{
	u32 addr;
	u32 data;
	return ptrace(PTRACE_CONT, pid, addr, data);
}

struct r_debug_handle_t {
	.step = &r_debug_ptrace_step,
	.cont = &r_debug_ptrace_continue,
	.attach = &r_debug_ptrace_attach,
	.detach = &r_debug_ptrace_detach,
};
#if 0
int r_debug_ptrace_init(struct r_debug_t *dbg)
{
	dbg->step = r_debug_ptrace_step;
	dbg->cont = r_debug_ptrace_continue;
	dbg->attach = r_debug_ptrace_attach;
	dbg->detach = r_debug_ptrace_detach;
	return R_TRUE;
}
#endif
