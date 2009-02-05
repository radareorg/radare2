/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>

int r_debug_init(struct r_debug_t *dbg)
{
	dbg->pid = -1;
	dbg->tid = -1;
	dbg->swstep = 0; // software step
	dbg->h = NULL;
	r_debug_handle_init(dbg);
	return R_TRUE;
}

struct r_debug_t *r_debug_new()
{
	struct r_debug_t *dbg;
	dbg = MALLOC_STRUCT(struct r_debug_t);
	r_debug_init(dbg);
	return dbg;
}

int r_debug_attach(struct r_debug_t *dbg, int pid)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->attach) {
		int ret = dbg->h->attach(pid);
		if (ret)
			dbg->pid = pid;
		else fprintf(stderr, "Cannot attach to this pid\n");
	} else fprintf(stderr, "dbg->attach = NULL\n");
	return ret;
}

int r_debug_startv(struct r_debug_t *dbg, int argc, char **argv)
{
	return R_FALSE;
}

int r_debug_start(struct r_debug_t *dbg, const char *cmd)
{
	return R_FALSE;
}

int r_debug_detach(struct r_debug_t *dbg, int pid)
{
	if (dbg->h && dbg->h->detach)
		return dbg->h->detach(pid);
	return R_FALSE;
}

int r_debug_select(struct r_debug_t *dbg, int pid, int tid)
{
	dbg->pid = pid;
	dbg->tid = tid;
	return R_TRUE;
}

int r_debug_set_arch(struct r_debug_t *dbg, int arch)
{
	switch(arch) {
	case R_ASM_ARCH_BF:
		// TODO: set callbacks for brainfuck debugger here
		break;
	case R_ASM_ARCH_X86:
		//r_reg_set(dbg->reg->nregs, R_ASM_ARCH_X86);
		break;
	}
	return R_TRUE;
}

/*--*/
int r_debug_stop_reason(struct r_debug_t *dbg)
{
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// ...
	return R_TRUE;
}

// TODO: count number of steps done to check if no error??
int r_debug_step(struct r_debug_t *dbg, int steps)
{
	int i, ret = R_FALSE;
	if (dbg->h && dbg->h->step) {
		for(i=0;i<steps;i++) {
			ret = dbg->h->step(dbg->pid);
			if (ret == R_FALSE)
				break;
			dbg->steps++;
		}
	}
	return ret;
}

int r_debug_syscall(struct r_debug_t *dbg, int num)
{
	fprintf(stderr, "TODO\n");
	return R_FALSE;
}

int r_debug_step_over(struct r_debug_t *dbg, int steps)
{
	// TODO: analyze opcode if it is stepoverable
	fprintf(stderr, "TODO\n");
	return r_debug_step(dbg, steps);
}

int r_debug_continue(struct r_debug_t *dbg)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->cont)
		ret = dbg->h->cont(dbg->pid);
	return ret;
}

int r_debug_continue_until(struct r_debug_t *dbg, u64 addr)
{
	return -1;
}

int r_debug_continue_syscall(struct r_debug_t *dbg, int sc)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->cont)
		ret = dbg->h->contsc(dbg->pid, sc);
	return ret;
}

// XXX wrong function name
int r_debug_use_software_steps(struct r_debug_t *dbg, int value)
{
	/* use software breakpoints and continues */
	return -1;
}

/* registers */

int r_debug_register_get(struct r_debug_t *dbg, int reg, u64 *value)
{
	return R_TRUE;
}

int r_debug_register_set(struct r_debug_t *dbg, int reg, u64 value)
{
	return R_TRUE;
}

/* mmu */

int r_debug_mmu_alloc(struct r_debug_t *dbg, u64 size, u64 *addr)
{
	return R_TRUE;
}

int r_debug_mmu_free(struct r_debug_t *dbg, u64 addr)
{
	return R_TRUE;
}
