/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>

R_API struct r_debug_t *r_debug_init(struct r_debug_t *dbg, int hard) {
	if (dbg) {
		dbg->pid = -1;
		dbg->tid = -1;
		dbg->swstep = 0; // software step
		dbg->newstate = 0;
		//dbg->regs = dbg->oregs = NULL;
		dbg->printf = (void *)printf;
		dbg->reg = r_reg_new ();
		dbg->h = NULL;
		/* TODO: this is not well designed */
		dbg->maps = r_debug_map_list_new ();
		dbg->maps_user = r_debug_map_list_new ();
		if (hard) {
			dbg->bp = r_bp_new ();
			r_debug_handle_init (dbg);
			dbg->bp->iob.init = R_FALSE;
		}
	}
	return dbg;
}

R_API struct r_debug_t *r_debug_new() {
	return r_debug_init (R_NEW (RDebug), R_TRUE);
}

R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg) {
	// TODO: free it correctly
	//r_bp_free(&dbg->bp);
	//r_reg_free(&dbg->reg);
	//r_debug_handle_free();
	free (dbg);
	return NULL;
}

R_API int r_debug_attach(struct r_debug_t *dbg, int pid) {
	int ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->attach) {
		ret = dbg->h->attach (pid);
		if (ret) {
			// TODO: get arch and set io pid
			//int arch = dbg->h->get_arch();
			//r_reg_set(dbg->reg->nregs, arch); //R_DBG_ARCH_X86);
			// dbg->bp->iob->system("pid %d", pid);
			dbg->pid = pid;
			dbg->tid = pid;
		} else eprintf ("Cannot attach to this pid\n");
	} else eprintf ("dbg->attach = NULL\n");
	return ret;
}

/* 
 * Save 4096 bytes from %esp
 * TODO: Add support for reverse stack architectures
 */
R_API ut64 r_debug_execute(struct r_debug_t *dbg, ut8 *buf, int len) {
	int orig_sz;
	ut8 stackbackup[4096];
	ut8 *backup, *orig = NULL;
	RRegisterItem *ri, *risp, *ripc;
	ut64 rsp, rpc, ra0 = 0LL;
	ripc = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], R_REG_TYPE_GPR);
	risp = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], R_REG_TYPE_GPR);
	if (ripc) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
		orig = r_reg_get_bytes (dbg->reg, -1, &orig_sz);
		if (orig == NULL) {
			eprintf ("Cannot get register arena bytes\n");
			return 0LL;
		}
		rpc = r_reg_get_value (dbg->reg, ripc);
		rsp = r_reg_get_value (dbg->reg, risp);

		backup = malloc (len);
		if (backup == NULL)
			return 0LL;
		dbg->iob.read_at (dbg->iob.io, rpc, backup, len);
		dbg->iob.read_at (dbg->iob.io, rsp, stackbackup, len);

		r_bp_add_sw (dbg->bp, rpc+len, 1, R_BP_PROT_EXEC);

		/* execute code here */
		dbg->iob.write_at (dbg->iob.io, rpc, buf, len);
		r_debug_continue (dbg);
		/* TODO: check if stopped in breakpoint or not */

		r_bp_del (dbg->bp, rpc+len);
		dbg->iob.write_at (dbg->iob.io, rpc, backup, len);
		dbg->iob.write_at (dbg->iob.io, rsp, stackbackup, len);

		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
		ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_A0], R_REG_TYPE_GPR);
		ra0 = r_reg_get_value (dbg->reg, ri);
		r_reg_set_bytes (dbg->reg, -1, orig, orig_sz);
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_TRUE);

		free (backup);
		free (orig);
		eprintf ("ra0=0x%08llx\n", ra0);
	} else eprintf ("r_debug_execute: Cannot get program counter\n");
	return (ra0);
}

R_API int r_debug_startv(struct r_debug_t *dbg, int argc, char **argv) {
	/* TODO : r_debug_startv unimplemented */
	return R_FALSE;
}

R_API int r_debug_start(struct r_debug_t *dbg, const char *cmd) {
	/* TODO: this argc/argv parser is done in r_io */
	// TODO: parse cmd and generate argc and argv
	return R_FALSE;
}

R_API int r_debug_detach(struct r_debug_t *dbg, int pid) {
	if (dbg->h && dbg->h->detach)
		return dbg->h->detach(pid);
	return R_FALSE;
}

R_API int r_debug_select(struct r_debug_t *dbg, int pid, int tid) {
	dbg->pid = pid;
	dbg->tid = tid;
	eprintf("PID: %d %d\n", pid, tid);
	return R_TRUE;
}

R_API int r_debug_stop_reason(struct r_debug_t *dbg) {
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// ...
	return R_TRUE;
}

R_API int r_debug_wait(struct r_debug_t *dbg) {
	int ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->wait) {
		ret = dbg->h->wait(dbg->pid);
		dbg->newstate = 1;
	}
	return ret;
}

// TODO: count number of steps done to check if no error??
R_API int r_debug_step(struct r_debug_t *dbg, int steps) {
	int i, ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->step) {
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

R_API void r_debug_io_bind(RDebug *dbg, RIO *io) {
	r_io_bind (io, &dbg->bp->iob);
	r_io_bind (io, &dbg->iob);
}

R_API int r_debug_step_over(struct r_debug_t *dbg, int steps) {
	// TODO: analyze opcode if it is stepoverable
	eprintf ("r_debug_step_over: TODO\n");
	return r_debug_step(dbg, steps);
}

/* restore program counter after breakpoint hit */
static int r_debug_recoil(struct r_debug_t *dbg) {
	int recoil, ret = R_FALSE;
	RRegisterItem *ri;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
	ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], -1);
	if (ri) {
		ut64 addr = r_reg_get_value (dbg->reg, ri);
		recoil = r_bp_recoil (dbg->bp, addr);
		eprintf("Breakpoint recoil = %d\n", recoil);
		if (recoil) {
			r_reg_set_value (dbg->reg, ri, addr-recoil);
			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_TRUE);
			ret = R_TRUE;
		}
	} else eprintf ("r_debug_recoil: Cannot get program counter\n");
	return ret;
}

R_API int r_debug_continue_kill(struct r_debug_t *dbg, int sig) {
	int ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->cont) {
		r_bp_restore (dbg->bp, R_FALSE); // set sw breakpoints
		ret = dbg->h->cont(dbg->pid, sig);
		if (dbg->h->wait)
			ret = dbg->h->wait(dbg->pid);
		r_bp_restore (dbg->bp, R_TRUE); // unset sw breakpoints
		r_debug_recoil (dbg);
	}
	return ret;
}

R_API int r_debug_continue(struct r_debug_t *dbg) {
	return r_debug_continue_kill (dbg, -1);
}

R_API int r_debug_continue_until(struct r_debug_t *dbg, ut64 addr) {
	//struct r_debug_bp_t *bp = r_debug_bp_add (dbg, addr);
	//int ret = r_debug_continue(dbg);
	/* TODO: check if the debugger stops at the right address */
	//r_debug_bp_del(dbg, bp);
	return -1;
}

R_API int r_debug_continue_syscall(struct r_debug_t *dbg, int sc) {
	int ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->contsc)
		ret = dbg->h->contsc(dbg->pid, sc);
	return ret;
}

// TODO: remove from here? this is code injection!
R_API int r_debug_syscall(struct r_debug_t *dbg, int num) {
	eprintf ("TODO\n");
	return R_FALSE;
}

R_API int r_debug_kill(struct r_debug_t *dbg, int sig) {
	int ret = R_FALSE;
	if (dbg->h && dbg->h->kill)
		ret = dbg->h->kill (dbg, sig);
	else eprintf ("Backend does not implements kill()\n");
	return ret;
}

// TODO: move into r_debug
// TODO: we need to know the arch backend, frame size, 
// TODO: merge algorithms from r1 (do we need ebp?)
// TODO: must return a linked list or r_iter
R_API int r_anal_backtrace(struct r_anal_t *anal, const ut8 *buf, ut64 esp) {
	return R_FALSE;
}
