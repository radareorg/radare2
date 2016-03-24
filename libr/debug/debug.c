/* radare - LGPL - Copyright 2009-2015 - pancake, TheLemonMan */

#include <r_debug.h>
#include <signal.h>

R_LIB_VERSION(r_debug);

// Size of the lookahead buffers used in r_debug functions
#define DBG_BUF_SIZE 512

R_API RDebugInfo *r_debug_info(RDebug *dbg, const char *arg) {
	if (!dbg || !dbg->h || !dbg->h->info)
		return NULL;
	return dbg->h->info (dbg, arg);
}

R_API void r_debug_info_free (RDebugInfo *rdi) {
	free (rdi->cwd);
	free (rdi->exe);
	free (rdi->cmdline);
	free (rdi->libname);
}

/* restore program counter after breakpoint hit */
static int r_debug_recoil(RDebug *dbg) {
	int recoil;
	RRegItem *ri;
	if (r_debug_is_dead (dbg))
		return false;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], -1);
	dbg->reason.bpi = NULL;
	if (ri) {
		ut64 addr = r_reg_get_value (dbg->reg, ri);
		recoil = r_bp_recoil (dbg->bp, addr);
		//eprintf ("[R2] Breakpoint recoil at 0x%"PFMT64x" = %d\n", addr, recoil);
		if (recoil < 1)
			recoil = 0; // XXX Hack :D
		if (recoil) {
			dbg->reason.type = R_DEBUG_REASON_BREAKPOINT;
			dbg->reason.bpi = r_bp_get_at (dbg->bp, addr-recoil);
			dbg->reason.addr = addr - recoil;
			r_reg_set_value (dbg->reg, ri, addr-recoil);
			if (r_reg_get_value (dbg->reg, ri) != (addr-recoil)) {
				eprintf ("r_debug_recoil: Cannot set program counter\n");
				return false;
			}
			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, true);
			//eprintf ("[BP Hit] Setting pc to 0x%"PFMT64x"\n", (addr-recoil));
			return true;
		}
	} else {
		eprintf ("r_debug_recoil: Cannot get program counter\n");
	}
	return false;
}

R_API RDebug *r_debug_new(int hard) {
	RDebug *dbg = R_NEW0 (RDebug);
	if (!dbg) return NULL;
	// R_SYS_ARCH
	dbg->arch = strdup (R_SYS_ARCH);
	dbg->bits = R_SYS_BITS;
	dbg->trace_forks = 1;
	dbg->trace_clone = 0;
	R_FREE (dbg->btalgo);
	dbg->trace_execs = 0;
	dbg->anal = NULL;
	dbg->snaps = r_list_newf (r_debug_snap_free);
	dbg->pid = -1;
	dbg->bpsize = 1;
	dbg->tid = -1;
	dbg->tree = r_tree_new ();
	dbg->tracenodes = sdb_new0 ();
	dbg->swstep = 0;
	dbg->newstate = 0;
	dbg->stop_all_threads = false;
	dbg->trace = r_debug_trace_new ();
	dbg->cb_printf = (void *)printf;
	dbg->reg = r_reg_new ();
	dbg->num = r_num_new (r_debug_num_callback, dbg);
	dbg->h = NULL;
	dbg->threads = NULL;
	/* TODO: needs a redesign? */
	dbg->maps = r_debug_map_list_new ();
	dbg->maps_user = r_debug_map_list_new ();
	r_debug_signal_init (dbg);
	if (hard) {
		dbg->bp = r_bp_new ();
		r_debug_plugin_init (dbg);
		dbg->bp->iob.init = false;
	}
	return dbg;
}

static int free_tracenodes_entry (RDebug *dbg, const char *k, const char *v) {
	ut64 v_num = r_num_get (NULL, v);
	free((void *)(size_t)v_num);
	return true;
}

R_API void r_debug_tracenodes_reset (RDebug *dbg) {
	sdb_foreach (dbg->tracenodes, (SdbForeachCallback)free_tracenodes_entry, dbg);
	sdb_reset (dbg->tracenodes);
}

R_API RDebug *r_debug_free(RDebug *dbg) {
	if (!dbg) return NULL;
	// TODO: free it correctly.. we must ensure this is an instance and not a reference..
	r_bp_free (dbg->bp);
	//r_reg_free(&dbg->reg);
	r_list_free (dbg->snaps);
	r_list_free (dbg->maps);
	r_list_free (dbg->maps_user);
	r_list_free (dbg->threads);
	sdb_free (dbg->sgnls);
	r_tree_free (dbg->tree);
	sdb_foreach (dbg->tracenodes, (SdbForeachCallback)free_tracenodes_entry, dbg);
	sdb_free (dbg->tracenodes);
	//r_debug_plugin_free();
	free (dbg->btalgo);
	r_debug_trace_free (dbg);
	free (dbg->arch);
	free (dbg->glob_libs);
	free (dbg->glob_unlibs);
	free (dbg);
	return NULL;
}

R_API int r_debug_attach(RDebug *dbg, int pid) {
	int ret = false;
	if (dbg && dbg->h && dbg->h->attach) {
		ret = dbg->h->attach (dbg, pid);
		if (ret != -1) {
			//eprintf ("Attached debugger to pid = %d, tid = %d\n", pid, ret);
			r_debug_select (dbg, pid, ret); //dbg->pid, dbg->tid);
		}
	}
	return ret;
}

/* stop execution of child process */
R_API int r_debug_stop(RDebug *dbg) {
	if (dbg && dbg->h && dbg->h->stop)
		return dbg->h->stop (dbg);
	return false;
}

R_API bool r_debug_set_arch(RDebug *dbg, const char *arch, int bits) {
	if (arch && dbg && dbg->h) {
		bool rc = r_sys_arch_match (dbg->h->arch, arch);
		if (rc) {
			switch (bits) {
			case 32:
				if (dbg->h->bits & R_SYS_BITS_32) {
					dbg->bits = R_SYS_BITS_32;
				}
				break;
			case 64:
				dbg->bits = R_SYS_BITS_64;
				break;
			}
			if (!dbg->h->bits) {
				dbg->bits = dbg->h->bits;
			} else if (!(dbg->h->bits & dbg->bits)) {
				dbg->bits = dbg->h->bits & R_SYS_BITS_64;
				if (!dbg->bits)
					dbg->bits = dbg->h->bits & R_SYS_BITS_32;
				if (!dbg->bits)
					dbg->bits = R_SYS_BITS_32;
				eprintf ("Invalid value for bits\n");
			}
			free (dbg->arch);
			dbg->arch = strdup (arch);
			return true;
		}
	}
	return false;
}

/*
 * Save 4096 bytes from %esp
 * TODO: Add support for reverse stack architectures
 * Also known as r_debug_inject()
 */
R_API ut64 r_debug_execute(RDebug *dbg, const ut8 *buf, int len, int restore) {
	int orig_sz;
	ut8 stackbackup[4096];
	ut8 *backup, *orig = NULL;
	RRegItem *ri, *risp, *ripc;
	ut64 rsp, rpc, ra0 = 0LL;
	if (r_debug_is_dead (dbg))
		return false;
	ripc = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], R_REG_TYPE_GPR);
	risp = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_SP], R_REG_TYPE_GPR);
	if (ripc) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		orig = r_reg_get_bytes (dbg->reg, -1, &orig_sz);
		if (orig == NULL) {
			eprintf ("Cannot get register arena bytes\n");
			return 0LL;
		}
		rpc = r_reg_get_value (dbg->reg, ripc);
		rsp = r_reg_get_value (dbg->reg, risp);

		backup = malloc (len);
		if (backup == NULL) {
			free (orig);
			return 0LL;
		}
		dbg->iob.read_at (dbg->iob.io, rpc, backup, len);
		dbg->iob.read_at (dbg->iob.io, rsp, stackbackup, len);

		r_bp_add_sw (dbg->bp, rpc+len, dbg->bpsize, R_BP_PROT_EXEC);

		/* execute code here */
		dbg->iob.write_at (dbg->iob.io, rpc, buf, len);
	//r_bp_add_sw (dbg->bp, rpc+len, 4, R_BP_PROT_EXEC);
		r_debug_continue (dbg);
	//r_bp_del (dbg->bp, rpc+len);
		/* TODO: check if stopped in breakpoint or not */

		r_bp_del (dbg->bp, rpc+len);
		dbg->iob.write_at (dbg->iob.io, rpc, backup, len);
		if (restore) {
			dbg->iob.write_at (dbg->iob.io, rsp, stackbackup, len);
		}

		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_A0], R_REG_TYPE_GPR);
		ra0 = r_reg_get_value (dbg->reg, ri);
		if (restore) {
			r_reg_read_regs (dbg->reg, orig, orig_sz);
		} else {
			r_reg_set_value (dbg->reg, ripc, rpc);
		}
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, true);
		free (backup);
		free (orig);
		eprintf ("ra0=0x%08"PFMT64x"\n", ra0);
	} else eprintf ("r_debug_execute: Cannot get program counter\n");
	return (ra0);
}

R_API int r_debug_startv(struct r_debug_t *dbg, int argc, char **argv) {
	/* TODO : r_debug_startv unimplemented */
	return false;
}

R_API int r_debug_start(RDebug *dbg, const char *cmd) {
	/* TODO: this argc/argv parser is done in r_io */
	// TODO: parse cmd and generate argc and argv
	return false;
}

R_API int r_debug_detach(RDebug *dbg, int pid) {
	if (dbg->h && dbg->h->detach)
		return dbg->h->detach (dbg, pid);
	return false;
}

R_API int r_debug_select(RDebug *dbg, int pid, int tid) {
	if (tid < 0)
		tid = pid;

	if (pid != -1 && tid != -1) {
		if (pid != dbg->pid || tid != dbg->tid)
			eprintf ("attach %d %d\n", pid, tid);
	} else {
		if (dbg->pid != -1)
			eprintf ("Child %d is dead\n", dbg->pid);
	}

	if (dbg->h && dbg->h->select && !dbg->h->select (pid, tid))
		return false;

	dbg->pid = pid;
	dbg->tid = tid;

	return true;
}

R_API const char *r_debug_reason_to_string(int type) {
	switch (type) {
	case R_DEBUG_REASON_DEAD: return "dead";
	case R_DEBUG_REASON_ABORT: return "abort";
	case R_DEBUG_REASON_SEGFAULT: return "segfault";
	case R_DEBUG_REASON_NONE: return "none";
	case R_DEBUG_REASON_SIGNAL: return "signal";
	case R_DEBUG_REASON_BREAKPOINT: return "breakpoint";
	case R_DEBUG_REASON_READERR: return "read-error";
	case R_DEBUG_REASON_WRITERR: return "write-error";
	case R_DEBUG_REASON_DIVBYZERO: return "div-by-zero";
	case R_DEBUG_REASON_ILLEGAL: return "illegal";
	case R_DEBUG_REASON_UNKNOWN: return "unknown";
	case R_DEBUG_REASON_ERROR: return "error";
	case R_DEBUG_REASON_NEW_PID: return "new-pid";
	case R_DEBUG_REASON_NEW_TID: return "new-tid";
	case R_DEBUG_REASON_NEW_LIB: return "new-lib";
	case R_DEBUG_REASON_EXIT_PID: return "exit-pid";
	case R_DEBUG_REASON_EXIT_TID: return "exit-tid";
	case R_DEBUG_REASON_EXIT_LIB: return "exit-lib";
	case R_DEBUG_REASON_TRAP: return "trap";
	case R_DEBUG_REASON_SWI: return "software-interrupt";
	case R_DEBUG_REASON_INT: return "interrupt";
	case R_DEBUG_REASON_FPU: return "fpu";
	case R_DEBUG_REASON_STEP: return "step";
	}
	return "unhandled";
}

R_API int r_debug_stop_reason(RDebug *dbg) {
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// return dbg->reason
	return dbg->reason.type;
}

/* Returns  R_DEBUG_REASON_* */
R_API int r_debug_wait(RDebug *dbg) {
	int ret = 0;
	if (!dbg)
		return false;
	dbg->reason.type = R_DEBUG_REASON_UNKNOWN;
	if (r_debug_is_dead (dbg))
		return dbg->reason.type = R_DEBUG_REASON_DEAD;
	if (dbg->h && dbg->h->wait) {
		dbg->reason.type = R_DEBUG_REASON_UNKNOWN;
		ret = dbg->h->wait (dbg, dbg->pid);
		dbg->newstate = 1;
		if (ret == -1) {
			eprintf ("\n==> Process finished\n\n");
			r_debug_select (dbg, -1, -1);
		}
		if (dbg->trace->enabled)
			r_debug_trace_pc (dbg);
		dbg->reason.type = ret;
		if (ret == R_DEBUG_REASON_SIGNAL && dbg->reason.signum != -1) {
			/* handle signal on continuations here */
			int what = r_debug_signal_what (dbg, dbg->reason.signum);
			const char *name = r_debug_signal_resolve_i (dbg, dbg->reason.signum);
			if (name && strcmp ("SIGTRAP", name))
				r_cons_printf ("[+] signal %d aka %s received %d\n",
						dbg->reason.signum, name, what);
		}
	}
	return ret;
}

R_API int r_debug_step_soft(RDebug *dbg) {
	ut8 buf[32];
	ut64 pc, sp;
	ut64 next[2];
	RAnalOp op;
	int br, i, ret;
	union {
		ut64 r64;
		ut32 r32[2];
	} sp_top;

	if (r_debug_is_dead (dbg))
		return false;

	pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	sp = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_SP]);

	if (dbg->iob.read_at) {
		if (dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf)) < 0)
			return false;
	} else {
		return false;
	}

	if (!r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf)))
		return false;

	if (op.type == R_ANAL_OP_TYPE_ILL)
		return false;

	switch (op.type) {
	case R_ANAL_OP_TYPE_RET:
		dbg->iob.read_at (dbg->iob.io, sp, (ut8 *)&sp_top, 8);
		next[0] = (dbg->bits == R_SYS_BITS_32) ? sp_top.r32[0] : sp_top.r64;
		br = 1;
		break;

	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_CCALL:
		next[0] = op.jump;
		next[1] = op.fail;
		br = 2;
		break;

	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
		next[0] = op.jump;
		br = 1;
		break;

	default:
		next[0] = op.addr + op.size;
		br = 1;
		break;
	}

	for (i = 0; i < br; i++)
		r_bp_add_sw (dbg->bp, next[i], dbg->bpsize, R_BP_PROT_EXEC);

	ret = r_debug_continue (dbg);

	for (i = 0; i < br; i++)
		r_bp_del (dbg->bp, next[i]);

	return ret;
}

R_API int r_debug_step_hard(RDebug *dbg) {
	dbg->reason.type = R_DEBUG_REASON_STEP;
	if (r_debug_is_dead (dbg))
		return false;
	if (!dbg->h->step (dbg))
		return false;
	return r_debug_wait (dbg);
}

R_API int r_debug_step(RDebug *dbg, int steps) {
	int i, ret;

	if (!dbg || !dbg->h)
		return false;
	dbg->reason.type = R_DEBUG_REASON_STEP;

	if (r_debug_is_dead (dbg)) {
		return false;
	}

	if (steps < 1)
		steps = 1;

	for (i = 0; i < steps; i++) {
		ret = dbg->swstep ?
			r_debug_step_soft (dbg):
			r_debug_step_hard (dbg);
		if (!ret) {
			eprintf ("Stepping failed!\n");
			return false;
		} else {
			dbg->steps++;
			dbg->reason.type = R_DEBUG_REASON_STEP;
			//dbg->reason.addr =
		}
	}

	return i;
}

R_API void r_debug_io_bind(RDebug *dbg, RIO *io) {
	r_io_bind (io, &dbg->bp->iob);
	r_io_bind (io, &dbg->iob);
}

R_API int r_debug_step_over(RDebug *dbg, int steps) {
	RAnalOp op;
	ut64 buf_pc, pc;
	ut8 buf[DBG_BUF_SIZE];
	int i;

	if (r_debug_is_dead (dbg))
		return false;

	if (steps < 1)
		steps = 1;

	if (dbg->h && dbg->h->step_over) {
		for (i = 0; i < steps; i++)
			if (!dbg->h->step_over (dbg))
				return false;
		return i;
	}

	if (!dbg->anal || !dbg->reg)
		return false;

	// Initial refill
	buf_pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));

	for (i = 0; i < steps; i++) {
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof (buf)) {
			buf_pc = pc;
			dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));
		}
		// Analyze the opcode
		if (!r_anal_op (dbg->anal, &op, pc, buf + (pc - buf_pc), sizeof (buf) - (pc - buf_pc))) {
			eprintf ("Decode error at %"PFMT64x"\n", pc);
			return false;
		}

		// Skip over all the subroutine calls
		if (op.type == R_ANAL_OP_TYPE_CALL  ||
			op.type == R_ANAL_OP_TYPE_CCALL ||
			op.type == R_ANAL_OP_TYPE_UCALL ||
			op.type == R_ANAL_OP_TYPE_UCCALL) {

			// Use op.fail here instead of pc+op.size to enforce anal backends to fill in this field
			if (!r_debug_continue_until (dbg, op.fail)) {
				eprintf ("Could not step over call @ 0x%"PFMT64x"\n", pc);
				return false;
			}
		} else if ((op.prefix & (R_ANAL_OP_PREFIX_REP | R_ANAL_OP_PREFIX_REPNE | R_ANAL_OP_PREFIX_LOCK))) {
			//eprintf ("REP: skip to next instruction...\n");
			if (!r_debug_continue_until (dbg, pc+op.size)) {
				eprintf ("step over failed over rep\n");
				return false;
			}
		} else r_debug_step (dbg, 1);
	}

	return i;
}

#if __WINDOWS__
void w32_break_process (void *);
#endif
R_API int r_debug_continue_kill(RDebug *dbg, int sig) {
	ut64 pc;
	int retwait, ret = false;
	if (!dbg)
		return false;
#if __WINDOWS__
	r_cons_break(w32_break_process, dbg);
#endif
repeat:
	if (r_debug_is_dead (dbg))
		return false;
	if (dbg->h && dbg->h->cont) {
		r_bp_restore (dbg->bp, true); // set sw breakpoints
		ret = dbg->h->cont (dbg, dbg->pid, dbg->tid, sig);
		dbg->reason.signum = 0;
		retwait = r_debug_wait (dbg);
#if __WINDOWS__
		if (retwait != R_DEBUG_REASON_DEAD) {
			ret = dbg->tid;
		}
		if (retwait == R_DEBUG_REASON_NEW_LIB ||
		    retwait == R_DEBUG_REASON_EXIT_LIB) {
			goto repeat;
		}
#endif
		if (r_debug_is_dead (dbg))
			return false;
		r_bp_restore (dbg->bp, false); // unset sw breakpoints
		if (r_debug_recoil (dbg) || (dbg->reason.type == R_DEBUG_REASON_BREAKPOINT)) {
			/* check if cur bp demands tracing or not */
			pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
			RBreakpointItem *b = r_bp_get_at (dbg->bp, pc);
			if (b) {
				/* check if cur bp demands tracing or not */
				if (b->trace)
					eprintf("hit tracepoit at: %"PFMT64x"\n",pc);
				else
					eprintf("hit breakpoint at: %"PFMT64x"\n",pc);
				if (dbg->trace->enabled)
					r_debug_trace_pc (dbg);
				// TODO: delegate this to RCore.bphit(RCore, RBreakopintItem)
				if (dbg->corebind.core && dbg->corebind.bphit) {
					dbg->corebind.bphit (dbg->corebind.core, b);
				}
				if (b->trace) {
					r_debug_step (dbg, 1);
					goto repeat;
				}
			}
		}
		r_debug_select (dbg, dbg->pid, ret);
		sig = 0; // clear continuation after signal if needed
		if (retwait == R_DEBUG_REASON_SIGNAL && dbg->reason.signum != -1) {
			int what = r_debug_signal_what (dbg, dbg->reason.signum);
			if (what & R_DBG_SIGNAL_CONT) {
				sig = dbg->reason.signum;
				eprintf ("Continue into the signal %d handler\n", sig);
				goto repeat;
			} else if (what & R_DBG_SIGNAL_SKIP) {
				// skip signal. requires skipping one instruction
				ut8 buf[64];
				RAnalOp op = {0};
				ut64 pc = r_debug_reg_get (dbg, "pc");
				dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
				r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf));
				if (op.size > 0) {
					const char *signame = r_debug_signal_resolve_i (dbg, dbg->reason.signum);
					r_debug_reg_set (dbg, "pc", pc+op.size);
					eprintf ("Skip signal %d handler %s\n",
						dbg->reason.signum, signame);
					goto repeat;
				} else {
					ut64 pc = r_debug_reg_get (dbg, "pc");
					eprintf ("Stalled with an exception at 0x%08"PFMT64x"\n", pc);
				}
			}
		}
	}
	return ret;
}

R_API int r_debug_continue(RDebug *dbg) {
	return r_debug_continue_kill (dbg, 0); //dbg->reason.signum);
}

R_API int r_debug_continue_until_nontraced(RDebug *dbg) {
	eprintf ("TODO\n");
	return false;
}

R_API int r_debug_continue_until_optype(RDebug *dbg, int type, int over) {
	int ret, n = 0;
	ut64 pc, buf_pc = 0;
	RAnalOp op;
	ut8 buf[DBG_BUF_SIZE];

	if (r_debug_is_dead (dbg)) {
		return false;
	}

	if (!dbg->anal || !dbg->reg) {
		eprintf ("Undefined pointer at dbg->anal\n");
		return false;
	}

	r_debug_step (dbg, 1);
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);

	// Initial refill
	buf_pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));

	// step first, we dont want to check current optype
	for (;;) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof (buf)) {
			buf_pc = pc;
			dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));
		}
		// Analyze the opcode
		if (!r_anal_op (dbg->anal, &op, pc, buf + (pc - buf_pc), sizeof (buf) - (pc - buf_pc))) {
			eprintf ("Decode error at %"PFMT64x"\n", pc);
			return false;
		}
		if (op.type == type)
			break;
		// Step over and repeat
		ret = over ?
			r_debug_step_over (dbg, 1) :
			r_debug_step (dbg, 1);

		if (!ret) {
			eprintf ("r_debug_step: failed\n");
			break;
		}
		n++;
	}

	return n;
}

R_API int r_debug_continue_until(RDebug *dbg, ut64 addr) {
	int has_bp;
	ut64 pc;

	if (r_debug_is_dead (dbg))
		return false;

	// Check if there was another breakpoint set at addr
	has_bp = r_bp_get_in (dbg->bp, addr, R_BP_PROT_EXEC) != NULL;
	if (!has_bp)
		r_bp_add_sw (dbg->bp, addr, dbg->bpsize, R_BP_PROT_EXEC);

	// Continue until the bp is reached
	for (;;) {
		if (r_debug_is_dead (dbg))
			break;

		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		if (pc == addr)
			break;
		if (r_bp_get_at (dbg->bp, pc))
                        break;
		r_debug_continue (dbg);
	}

	// Clean up if needed
	if (!has_bp)
		r_bp_del (dbg->bp, addr);

	return true;
}

static int show_syscall(RDebug *dbg, const char *sysreg) {
	const char *sysname;
	char regname[8];
	int reg, i, args;
	RSyscallItem *si;
	reg = (int)r_debug_reg_get (dbg, sysreg);
	si = r_syscall_get (dbg->anal->syscall, reg, -1);
	if (si) {
		sysname = si->name? si->name: "unknown";
		args = si->args;
	} else {
		sysname = "unknown";
		args = 3;
	}
	eprintf ("--> %s 0x%08"PFMT64x" syscall %d %s (", sysreg,
			r_debug_reg_get (dbg, "pc"), reg, sysname);
	for (i=0; i<args; i++) {
		ut64 val;
		snprintf (regname, sizeof (regname)-1, "A%d", i);
		val = r_debug_reg_get (dbg, regname);
		if (((st64)val<0) && ((st64)val>-0xffff)) {
			eprintf ("%"PFMT64d"%s", val, (i+1==args)?"":" ");
		} else {
			eprintf ("0x%"PFMT64x"%s", val, (i+1==args)?"":" ");
		}
	}
	eprintf (")\n");
	r_syscall_item_free (si);
	return reg;
}

R_API int r_debug_continue_syscalls(RDebug *dbg, int *sc, int n_sc) {
	int i, reg, ret = false;
	if (!dbg || !dbg->h || r_debug_is_dead (dbg))
		return false;
	if (!dbg->h->contsc) {
		/* user-level syscall tracing */
		r_debug_continue_until_optype (dbg, R_ANAL_OP_TYPE_SWI, 0);
		return show_syscall (dbg, "A0");
	}

	if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
		eprintf ("--> cannot read registers\n");
		return -1;
	}
	{
		int err;
		reg = (int)r_debug_reg_get_err (dbg, "SN", &err);
		if (err) {
			eprintf ("Cannot find 'sn' register for current arch-os.\n");
			return -1;
		}
	}
	for (;;) {
		if (r_cons_singleton()->breaked)
			break;
#if __linux__
		// step is needed to avoid dupped contsc results
		r_debug_step (dbg, 1);
#endif
		dbg->h->contsc (dbg, dbg->pid, 0); // TODO handle return value
		// wait until continuation
		r_debug_wait (dbg);
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			eprintf ("--> cannot sync regs, process is probably dead\n");
			return -1;
		}
		reg = show_syscall (dbg, "SN");
		if (n_sc == -1)
			continue;
		if (n_sc == 0) {
			break;
		}
		for (i=0; i<n_sc; i++) {
			if (sc[i] == reg)
				return reg;
		}
		// TODO: must use r_core_cmd(as)..import code from rcore
	}
	return ret;
}

R_API int r_debug_continue_syscall(RDebug *dbg, int sc) {
	return r_debug_continue_syscalls (dbg, &sc, 1);
}

// TODO: remove from here? this is code injection!
R_API int r_debug_syscall(RDebug *dbg, int num) {
	bool ret = false;
	if (dbg->h->contsc) {
		ret = dbg->h->contsc (dbg, dbg->pid, num);
	} else {
		ret = true;
		// TODO.check for num
	}
	eprintf ("TODO: show syscall information\n");
	/* r2rc task? ala inject? */
	return (int)ret;
}

R_API int r_debug_kill(RDebug *dbg, int pid, int tid, int sig) {
	int ret = false;
	if (r_debug_is_dead (dbg))
		return false;
	if (dbg->h && dbg->h->kill)
		ret = dbg->h->kill (dbg, pid, tid, sig);
	else eprintf ("Backend does not implements kill()\n");
	return ret;
}

R_API RList *r_debug_frames(RDebug *dbg, ut64 at) {
	if (dbg && dbg->h && dbg->h->frames)
		return dbg->h->frames (dbg, at);
	return NULL;
}

/* TODO: Implement fork and clone */
R_API int r_debug_child_fork(RDebug *dbg) {
	//if (dbg && dbg->h && dbg->h->frames)
		//return dbg->h->frames (dbg);
	return 0;
}

R_API int r_debug_child_clone(RDebug *dbg) {
	//if (dbg && dbg->h && dbg->h->frames)
		//return dbg->h->frames (dbg);
	return 0;
}

R_API int r_debug_is_dead(RDebug *dbg) {
	int is_dead = (dbg->pid == -1);
	if (is_dead) {
		dbg->reason.type = R_DEBUG_REASON_DEAD;
	}
	return is_dead;
}

R_API int r_debug_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
	if (dbg && dbg->h && dbg->h->map_protect)
		return dbg->h->map_protect (dbg, addr, size, perms);
	return false;
}

R_API void r_debug_drx_list(RDebug *dbg) {
	if (dbg && dbg->h && dbg->h->drx)
		dbg->h->drx (dbg, 0, 0, 0, 0, 0);
}

R_API int r_debug_drx_set(RDebug *dbg, int idx, ut64 addr, int len, int rwx, int g) {
	if (dbg && dbg->h && dbg->h->drx)
		return dbg->h->drx (dbg, idx, addr, len, rwx, g);
	return false;
}

R_API int r_debug_drx_unset(RDebug *dbg, int idx) {
	if (dbg && dbg->h && dbg->h->drx)
		return dbg->h->drx (dbg, idx, 0, -1, 0, 0);
	return false;
}
