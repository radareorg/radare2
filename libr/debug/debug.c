/* radare - LGPL - Copyright 2009-2012 - pancake */

#include <r_debug.h>
#include <r_anal.h>
#include <signal.h>

/* restore program counter after breakpoint hit */
static int r_debug_recoil(RDebug *dbg) {
	int recoil;
	RRegItem *ri;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
	ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], -1);
	if (ri) {
		ut64 addr = r_reg_get_value (dbg->reg, ri);
		recoil = r_bp_recoil (dbg->bp, addr);
		eprintf ("[R2] Breakpoint recoil at 0x%"PFMT64x" = %d\n", addr, recoil);
		if (recoil<1) recoil = 1; // XXX Hack :D
		if (recoil) {
			dbg->reason = R_DBG_REASON_BP;
			r_reg_set_value (dbg->reg, ri, addr-recoil);
			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_TRUE);
			//eprintf ("[BP Hit] Setting pc to 0x%"PFMT64x"\n", (addr-recoil));
			return R_TRUE;
		} 
	} else eprintf ("r_debug_recoil: Cannot get program counter\n");
	return R_FALSE;
}

R_API RDebug *r_debug_new(int hard) {
	RDebug *dbg = R_NEW (RDebug);
	if (dbg) {
		// R_SYS_ARCH
		dbg->arch = r_sys_arch_id (R_SYS_ARCH); // 0 is native by default
		dbg->bits = R_SYS_BITS;
		dbg->anal = NULL;
		dbg->pid = -1;
		dbg->tid = -1;
		dbg->graph = r_graph_new ();
		dbg->swstep = 0;
		dbg->newstate = 0;
		dbg->reason = R_DBG_REASON_UNKNOWN;
		dbg->stop_all_threads = R_FALSE;
		dbg->trace = r_debug_trace_new ();
		dbg->printf = (void *)printf;
		dbg->reg = r_reg_new ();
		dbg->h = NULL;
		/* TODO: needs a redesign? */
		dbg->maps = r_debug_map_list_new ();
		dbg->maps_user = r_debug_map_list_new ();
		if (hard) {
			dbg->bp = r_bp_new ();
			r_debug_plugin_init (dbg);
			dbg->bp->iob.init = R_FALSE;
		}
	}
	return dbg;
}

R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg) {
	if (!dbg) return NULL;
	// TODO: free it correctly.. we must ensure this is an instance and not a reference..
	//r_bp_free(&dbg->bp);
	//r_reg_free(&dbg->reg);
	//r_debug_plugin_free();
	r_graph_free (dbg->graph);
	free (dbg);
	return NULL;
}

R_API int r_debug_attach(RDebug *dbg, int pid) {
	int ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->attach) {
		ret = dbg->h->attach (dbg, pid);
		if (ret != -1) {
			eprintf ("pid = %d tid = %d\n", pid, ret);
			// TODO: get arch and set io pid
			//int arch = dbg->h->arch;
			//r_reg_set(dbg->reg->nregs, arch); //R_DBG_ARCH_X86);
			// dbg->bp->iob->system("pid %d", pid);
			//dbg->pid = pid;
			//dbg->tid = ret;
			r_debug_select (dbg, pid, ret); //dbg->pid, dbg->tid);
		}// else if (pid != -1)
		//	eprintf ("Cannot attach to this pid %d\n", pid);
	} else eprintf ("dbg->attach = NULL\n");
	return ret;
}

/* stop execution of child process */
R_API int r_debug_stop(RDebug *dbg) {
	if (dbg && dbg->h && dbg->h->stop)
		return dbg->h->stop (dbg);
	return R_FALSE;
}

R_API int r_debug_set_arch(RDebug *dbg, int arch, int bits) {
	if (dbg && dbg->h) {
		if (arch & dbg->h->arch) {
			//eprintf ("arch supported by debug backend (%x)\n", arch);
			switch (bits) {
			case 32:
				dbg->bits = R_SYS_BITS_32;
				break;
			case 64:
				dbg->bits = R_SYS_BITS_64;
				break;
			}
			if (!(dbg->h->bits & dbg->bits))
				dbg->bits = dbg->h->bits;
			dbg->arch = arch;
			return R_TRUE;
		}
		//eprintf ("arch (%s, %d) not supported by debug backend\n",
		//	r_sys_arch_str (arch), bits);
	}
	return R_FALSE;
}

/* 
 * Save 4096 bytes from %esp
 * TODO: Add support for reverse stack architectures
 */
R_API ut64 r_debug_execute(struct r_debug_t *dbg, ut8 *buf, int len) {
	int orig_sz;
	ut8 stackbackup[4096];
	ut8 *backup, *orig = NULL;
	RRegItem *ri, *risp, *ripc;
	ut64 rsp, rpc, ra0 = 0LL;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
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
		eprintf ("ra0=0x%08"PFMT64x"\n", ra0);
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

R_API int r_debug_select(RDebug *dbg, int pid, int tid) {
	if (pid != dbg->pid || tid != dbg->tid)
		eprintf ("r_debug_select: %d %d\n", pid, tid);
	dbg->pid = pid;
	if (tid == -1)
		tid = dbg->pid;
	dbg->tid = tid;
	return R_TRUE;
}

R_API int r_debug_stop_reason(RDebug *dbg) {
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// return dbg->reason
	return dbg->reason;
}

/* Returns PID */
R_API int r_debug_wait(RDebug *dbg) {
	int ret = 0;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (dbg && dbg->h && dbg->h->wait) {
		dbg->reason = R_DBG_REASON_UNKNOWN;
		ret = dbg->h->wait (dbg, dbg->pid);
		dbg->reason = ret;
		dbg->newstate = 1;
		if (ret == -1) {
			eprintf ("\n==> Process finished\n\n");
			r_debug_select (dbg, -1, -1); //dbg->pid = -1;
		}
		//eprintf ("wait = %d\n", ret);
		if (dbg->trace->enabled)
			r_debug_trace_pc (dbg);
	}
	return ret;
}

// XXX: very experimental
R_API int r_debug_step_soft(RDebug *dbg) {
	int ret;
	ut8 buf[32];
	RAnalOp op;
	ut64 pc0, pc1, pc2;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	pc0 = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	dbg->iob.read_at (dbg->iob.io, pc0, buf, sizeof (buf));
	ret = r_anal_op (dbg->anal, &op, pc0, buf, sizeof (buf));
//eprintf ("read from pc0 = 0x%llx\n", pc0);
	pc1 = pc0 + op.length;
//eprintf ("oplen = %d\n", op.length);
//eprintf ("breakpoint at pc1 = 0x%llx\n", pc1);
	// XXX: Does not works for 'ret'
	pc2 = op.jump? op.jump: 0;
//eprintf ("breakpoint 2 at pc2 = 0x%llx\n", pc2);

	r_bp_add_sw (dbg->bp, pc1, 4, R_BP_PROT_EXEC);
	//if (pc2) r_bp_add_sw (dbg->bp, pc2, 4, R_BP_PROT_EXEC);
	r_debug_continue (dbg);
//eprintf ("wait\n");
	//r_debug_wait (dbg);
//eprintf ("del\n");
	r_bp_del (dbg->bp, pc1);
	if (pc2) r_bp_del (dbg->bp, pc2);

	return ret;
}

R_API int r_debug_step_hard(RDebug *dbg) {
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (!dbg->h->step (dbg))
		return R_FALSE;
	r_debug_wait (dbg);
	/* return value ignored? */
	return R_TRUE;
}

// TODO: count number of steps done to check if no error??
R_API int r_debug_step(RDebug *dbg, int steps) {
	int i, ret = R_FALSE;
	if (dbg && dbg->h && dbg->h->step) {
		for (i=0; i<steps; i++) {
			ret = (dbg->swstep)?
				r_debug_step_soft (dbg):
				r_debug_step_hard (dbg);
			// TODO: create wrapper for dbg_wait
			// TODO: check return value of wait and show error
			if (ret)
				dbg->steps++;
		}
	}
	return ret;
}

R_API void r_debug_io_bind(RDebug *dbg, RIO *io) {
	r_io_bind (io, &dbg->bp->iob);
	r_io_bind (io, &dbg->iob);
}

R_API int r_debug_step_over(RDebug *dbg, int steps) {
	RAnalOp op;
	ut8 buf[64];
	int ret = -1;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (dbg->h && dbg->h->step_over) {
		if (steps<1) steps = 1;
		while (steps--)
			if (!dbg->h->step_over (dbg))
				return R_FALSE;
		return R_TRUE;
	}
	if (dbg->anal && dbg->reg) {
		ut64 pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
		r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf));
		if (op.type & R_ANAL_OP_TYPE_CALL
		   || op.type & R_ANAL_OP_TYPE_UCALL) {
			ut64 bpaddr = pc + op.length;
			r_bp_add_sw (dbg->bp, bpaddr, 1, R_BP_PROT_EXEC);
			ret = r_debug_continue (dbg);
			r_bp_del (dbg->bp, bpaddr);
		} else {
			ret = r_debug_step (dbg, 1);
		}
	} else eprintf ("Undefined debugger backend\n");
	return ret;
}

R_API int r_debug_kill_setup(RDebug *dbg, int sig, int action) {
	// TODO: implement r_debug_kill_setup
	return R_FALSE;
}

R_API int r_debug_continue_kill(RDebug *dbg, int sig) {
	int ret = R_FALSE;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (dbg && dbg->h && dbg->h->cont) {
		r_bp_restore (dbg->bp, R_FALSE); // set sw breakpoints
		ret = dbg->h->cont (dbg, dbg->pid, dbg->tid, sig);
		r_debug_wait (dbg);
		r_bp_restore (dbg->bp, R_TRUE); // unset sw breakpoints
		r_debug_recoil (dbg);
#if 0
#if __UNIX__
		/* XXX Uh? */
		if (dbg->stop_all_threads && dbg->pid>0)
			r_sandbox_kill (dbg->pid, SIGSTOP);
#endif
#endif
		r_debug_select (dbg, dbg->pid, ret);
	}
	return ret;
}

R_API int r_debug_continue(RDebug *dbg) {
	return r_debug_continue_kill (dbg, -1);
}

R_API int r_debug_continue_until_nontraced(RDebug *dbg) {
	eprintf ("TODO\n");
	return R_FALSE;
}

/* optimization: avoid so many reads */
R_API int r_debug_continue_until_optype(RDebug *dbg, int type, int over) {
	int (*step)(RDebug *d, int n);
	int ret, n = 0;
	ut64 pc = 0;
	RAnalOp op;
	ut8 buf[64];

	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (dbg->anal && dbg->reg) {
		const char *pcreg = dbg->reg->name[R_REG_NAME_PC];
		step = over? r_debug_step_over: r_debug_step;
		for (;;) {
			pc = r_debug_reg_get (dbg, pcreg);
			dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
			ret = r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf));
			if (ret>0 && op.type&type)
				break;
			if (!step (dbg, 1)) {
				eprintf ("r_debug_step: failed\n");
				break;
			}
			n++;
		}
	} else eprintf ("Undefined pointer at dbg->anal\n");
	return n;
}

R_API int r_debug_continue_until(struct r_debug_t *dbg, ut64 addr) {
// TODO: use breakpoint+continue... more efficient
	int n = 0;
	ut64 pc = 0;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	do {
		if (pc !=0) r_debug_step (dbg, 1);
		n++;
	} while (pc != addr && !r_debug_is_dead (dbg));
	return n;
	//struct r_debug_bp_t *bp = r_debug_bp_add (dbg, addr);
	//int ret = r_debug_continue(dbg);
	/* TODO: check if the debugger stops at the right address */
	//r_debug_bp_del(dbg, bp);
	//return -1;
}

// XXX: this function uses 'oeax' which is linux-i386-specific
R_API int r_debug_continue_syscall(struct r_debug_t *dbg, int sc) {
	int reg, ret = R_FALSE;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (dbg && dbg->h) {
		if (dbg->h->contsc) {
			do {
				ret = dbg->h->contsc (dbg, dbg->pid, sc);
				if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE)) {
					eprintf ("--> eol\n");
					sc = 0;
					break;
				}
				reg = (int)r_debug_reg_get (dbg, "oeax"); // XXX
				eprintf ("--> syscall %d\n", reg);
				if (reg == 0LL)
					break;
				// TODO: must use r_core_cmd(as)..import code from rcore
			} while (sc != 0 && sc != reg);
		} else {
			r_debug_continue_until_optype (dbg, R_ANAL_OP_TYPE_SWI, 0);
			reg = (int)r_debug_reg_get (dbg, "oeax"); // XXX
			eprintf ("--> syscall %d\n", reg);
		}
	}
	return ret;
}

// TODO: remove from here? this is code injection!
R_API int r_debug_syscall(RDebug *dbg, int num) {
	int ret = R_FALSE;
	if (dbg->h->contsc) {
		ret = dbg->h->contsc (dbg, dbg->pid, num);
	} else {
		ret = R_TRUE;
		// TODO.check for num
	}
	eprintf ("TODO: show syscall information\n");
	/* r2rc task? ala inject? */
	return ret;
}

R_API int r_debug_kill(RDebug *dbg, int pid, int tid, int sig) {
	int ret = R_FALSE;
	if (r_debug_is_dead (dbg))
		return R_FALSE;
	if (dbg->h && dbg->h->kill)
		ret = dbg->h->kill (dbg, pid, tid, sig);
	else eprintf ("Backend does not implements kill()\n");
	return ret;
}

R_API RList *r_debug_frames (RDebug *dbg, ut64 at) {
	if (dbg && dbg->h && dbg->h->frames)
		return dbg->h->frames (dbg, at);
	return NULL;
}

/* TODO: Implement fork and clone */
R_API int r_debug_fork (RDebug *dbg) {
	//if (dbg && dbg->h && dbg->h->frames)
		//return dbg->h->frames (dbg);
	return 0;
}

R_API int r_debug_clone (RDebug *dbg) {
	//if (dbg && dbg->h && dbg->h->frames)
		//return dbg->h->frames (dbg);
	return 0;
}

R_API int r_debug_is_dead (RDebug *dbg) {
	return (dbg->pid == -1);
}

R_API int r_debug_map_protect (RDebug *dbg, ut64 addr, int size, int perms) {
	if (dbg && dbg->h && dbg->h->map_protect)
		return dbg->h->map_protect (dbg, addr, size, perms);
	return R_FALSE;
}
