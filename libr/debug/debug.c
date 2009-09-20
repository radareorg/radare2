/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>

R_API int r_debug_init(struct r_debug_t *dbg, int hard)
{
	dbg->pid = -1;
	dbg->tid = -1;
	dbg->swstep = 0; // software step
	dbg->newstate = 0;
	dbg->regs = dbg->oregs = NULL;
	dbg->printf = (void *)printf;
	dbg->reg = r_reg_new();
	dbg->h = NULL;
	if (hard) {
		dbg->bp = r_bp_new();
		r_debug_handle_init(dbg);
		dbg->bp->iob.init = R_FALSE;
	}
	return R_TRUE;
}

R_API struct r_debug_t *r_debug_new()
{
	struct r_debug_t *dbg = MALLOC_STRUCT(struct r_debug_t);
	if (dbg != NULL)
		r_debug_init(dbg, R_TRUE);
	return dbg;
}

R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg)
{
	// TODO: free it correctly
	//r_bp_free(&dbg->bp);
	free(dbg);
	return NULL;
}

R_API int r_debug_attach(struct r_debug_t *dbg, int pid)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->attach) {
		ret = dbg->h->attach(pid);
		if (ret) {
			// TODO: get arch and set io pid
			//int arch = dbg->h->get_arch();
			//r_reg_set(dbg->reg->nregs, arch); //R_DBG_ARCH_X86);
			// dbg->bp->iob->system("pid %d", pid);
			dbg->pid = pid;
			dbg->tid = pid;
		} else fprintf(stderr, "Cannot attach to this pid\n");
	} else fprintf(stderr, "dbg->attach = NULL\n");
	return ret;
}

R_API int r_debug_startv(struct r_debug_t *dbg, int argc, char **argv)
{
	return R_FALSE;
}

R_API int r_debug_start(struct r_debug_t *dbg, const char *cmd)
{
	// TODO: parse cmd and generate argc and argv
	return R_FALSE;
}

R_API int r_debug_detach(struct r_debug_t *dbg, int pid)
{
	if (dbg->h && dbg->h->detach)
		return dbg->h->detach(pid);
	return R_FALSE;
}

R_API int r_debug_select(struct r_debug_t *dbg, int pid, int tid)
{
	dbg->pid = pid;
	dbg->tid = tid;
	eprintf("PID: %d %d\n", pid, tid);
	return R_TRUE;
}

/*--*/
R_API int r_debug_stop_reason(struct r_debug_t *dbg)
{
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// ...
	return R_TRUE;
}

R_API int r_debug_wait(struct r_debug_t *dbg)
{
	int ret = R_FALSE;
	if (dbg->h->wait) {
		ret = dbg->h->wait(dbg->pid);
		dbg->newstate = 1;
	}
	return ret;
}

// TODO: count number of steps done to check if no error??
R_API int r_debug_step(struct r_debug_t *dbg, int steps)
{
	int i, ret = R_FALSE;
	if (dbg->h && dbg->h->step) {
		for(i=0;i<steps;i++) {
			ret = dbg->h->step(dbg->pid);
			if (ret == R_FALSE)
				break;
			r_debug_wait(dbg);
			// TODO: create wrapper for dbg_wait
			// TODO: check return value of wait and show error
			dbg->steps++;
		}
	}
	return ret;
}

R_API int r_debug_step_over(struct r_debug_t *dbg, int steps)
{
	// TODO: analyze opcode if it is stepoverable
	fprintf(stderr, "TODO\n");
	return r_debug_step(dbg, steps);
}

R_API int r_debug_continue(struct r_debug_t *dbg)
{
	int ret = R_FALSE;
	if (dbg->h){
		if (dbg->h->cont) {
			ret = dbg->h->cont(dbg->pid);
			if (dbg->h->wait)
				ret = dbg->h->wait(dbg->pid);
		}
	}
	return ret;
}

R_API int r_debug_continue_until(struct r_debug_t *dbg, ut64 addr)
{
	//struct r_debug_bp_t *bp = r_debug_bp_add (dbg, addr);
	//int ret = r_debug_continue(dbg);
	/* TODO: check if the debugger stops at the right address */
	//r_debug_bp_del(dbg, bp);
	return -1;
}

R_API int r_debug_continue_syscall(struct r_debug_t *dbg, int sc)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->contsc)
		ret = dbg->h->contsc(dbg->pid, sc);
	return ret;
}

// TODO: remove from here?
R_API int r_debug_syscall(struct r_debug_t *dbg, int num)
{
	fprintf(stderr, "TODO\n");
	return R_FALSE;
}

// TODO: Move to pid.c ?
// TODO: do we need tid/pid
// TODO: Do we need an intermediate signal representation for portability?
// TODO: STOP, CONTINUE, KILL, ...
R_API int r_debug_kill(struct r_debug_t *dbg, int pid, int sig)
{
	// XXX: use debugger handler backend here
#include <signal.h>
	int ret = kill(pid, sig);
	if (ret == -1)
		return R_FALSE;
	return R_TRUE;
}

// TODO move to mem.c
/* mmu */
R_API ut64 r_debug_mmu_alloc(struct r_debug_t *dbg, ut64 size, ut64 addr)
{
	ut64 ret = 0LL;
	if (dbg->h && dbg->h->mmu_alloc)
		ret = dbg->h->mmu_alloc(dbg, size, addr);
	return ret;
}

R_API int r_debug_mmu_free(struct r_debug_t *dbg, ut64 addr)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->mmu_free)
		ret = dbg->h->mmu_free(dbg, addr);
	return ret;
}
// TODO: add support to iterate over all allocated memory chunks?
