/* radare - LGPL - Copyright 2009-2025 - pancake, jduck, TheLemonMan, saucec0de */

#include <r_core.h>
#include <r_drx.h>

R_LIB_VERSION(r_debug);

// Size of the lookahead buffers used in r_debug functions
#define DBG_BUF_SIZE 512

R_API RDebugInfo *r_debug_info(RDebug *dbg, const char *arg) {
	R_RETURN_VAL_IF_FAIL (dbg, NULL);
	if (dbg->pid < 0) {
		return NULL;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	return plugin->info? plugin->info (dbg, arg): NULL;
}

R_API void r_debug_info_free(RDebugInfo *rdi) {
	if (rdi) {
		free (rdi->cwd);
		free (rdi->exe);
		free (rdi->cmdline);
		free (rdi->libname);
		free (rdi->usr);
		free (rdi);
	}
}

R_API void r_debug_bp_update(RDebug *dbg) {
	/* update all bp->addr if they are named bps */
	RBreakpointItem *bp;
	RListIter *iter;
	r_list_foreach (dbg->bp->bps, iter, bp) {
		if (bp->expr) {
			bp->addr = dbg->coreb.numGet (dbg->coreb.core, bp->expr);
		}
	}
}

R_API int r_debug_drx_get(RDebug *dbg, ut64 addr) {
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->drx) {
		return plugin->drx (dbg, 0, addr, 0, 0, 0, DRX_API_GET_BP);
	}
	return -1;
}

/*
 * Recoiling after a breakpoint has two stages:
 * 1. remove the breakpoint and fix the program counter.
 * 2. on resume, single step once and then replace the breakpoint.
 *
 * Thus, we have two functions to handle these situations.
 * r_debug_bp_hit handles stage 1.
 * r_debug_recoil handles stage 2.
 */
static bool r_debug_bp_hit(RDebug *dbg, RRegItem *pc_ri, ut64 pc, RBreakpointItem **pb) {
	R_RETURN_VAL_IF_FAIL (dbg && pc_ri && pb, false);
	RBreakpointItem *b = NULL;
	/* initialize the output parameter */
	*pb = NULL;
#if 0
	/* if we are tracing, update the tracing data */
	// uncommenting this line causes the trace to be dupped
	if (dbg->trace->enabled) {
		r_debug_trace_pc (dbg, pc);
	}
#endif
	/* remove all sw breakpoints for now. we'll set them back in stage 2
	 *
	 * this is necessary because while stopped we don't want any breakpoints in
	 * the code messing up our analysis.
	 */
	r_debug_bp_update (dbg);
	if (!r_bp_restore (dbg->bp, false)) { // unset sw breakpoints
		return false;
	}

	/* if we are recoiling, tell r_debug_step that we ignored a breakpoint
	 * event */
	if (!dbg->swstep && dbg->recoil_mode != R_DBG_RECOIL_NONE) {
		dbg->reason.bp_addr = 0;
		return true;
	}

	/* The MIPS ptrace has a different behaviour */
# if __mips__
	/* see if we really have a breakpoint here... */
	b = r_bp_get_at (dbg->bp, pc);
	if (!b) { /* we don't. nothing left to do */
		return true;
	}
# else
	int pc_off = dbg->bpsize;
	/* see if we really have a breakpoint here... */
	if (!dbg->pc_at_bp_set) {
		b = r_bp_get_at (dbg->bp, pc - dbg->bpsize);
		if (!b) { /* we don't. nothing left to do */
			/* Some targets set pc to breakpoint */
			b = r_bp_get_at (dbg->bp, pc);
#if __i386__ || __x86_64__
			if (!b) {
				/* handle the case of hw breakpoints - notify the user */
				int drx_reg_idx = r_debug_drx_get (dbg, pc);
				if (drx_reg_idx != -1) {
					R_LOG_INFO ("hit hardware breakpoint %d at: %" PFMT64x,
						drx_reg_idx, pc);
				}
				/* Couldn't find the break point. Nothing more to do... */
				return true;
			}
#endif
			dbg->pc_at_bp_set = true;
			dbg->pc_at_bp = true;
		} else {
			dbg->pc_at_bp_set = true;
			dbg->pc_at_bp = false;
		}
	}

	if (!dbg->pc_at_bp_set) {
		R_LOG_ERROR ("failed to determine position of pc after breakpoint");
	}

	if (dbg->pc_at_bp) {
		pc_off = 0;
		b = r_bp_get_at (dbg->bp, pc);
	} else {
		b = r_bp_get_at (dbg->bp, pc - dbg->bpsize);
	}

	if (!b) {
		return true;
	}

	b = r_bp_get_at (dbg->bp, pc - dbg->bpsize);
	if (!b) { /* we don't. nothing left to do */
		/* Some targets set pc to breakpoint */
		b = r_bp_get_at (dbg->bp, pc);
		if (!b) {
			return true;
		}
		pc_off = 0;
	}

	/* set the pc value back */
	if (pc_off) {
		pc -= pc_off;
		if (!r_reg_set_value (dbg->reg, pc_ri, pc)) {
			R_LOG_ERROR ("failed to set PC");
			return false;
		}
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, true)) {
			R_LOG_ERROR ("cannot set registers");
			return false;
		}
	}
# endif
	*pb = b;

	/* if we are on a software stepping breakpoint, we hide what is going on... */
	if (b->swstep) {
		dbg->reason.bp_addr = 0;
		return true;
	}

	/* setup our stage 2 */
	dbg->reason.bp_addr = b->addr;

	/* inform the user of what happened */
	if (dbg->hitinfo) {
		R_LOG_INFO ("hit %spoint at: 0x%" PFMT64x,
			b->trace ? "trace" : "break", pc);
	}

	/* now that we've cleaned up after the breakpoint, call the other
	 * potential breakpoint handlers
	 */
	if (dbg->coreb.core && dbg->coreb.bpHit) {
		dbg->coreb.bpHit (dbg->coreb.core, b);
	}
	return true;
}

/* enable all software breakpoints */
static int r_debug_bps_enable(RDebug *dbg) {
	// restore all breakpoints. before step/continue this needs to be in place
	if (!r_bp_restore (dbg->bp, true)) {
		return false;
	}
	// recoiling done
	dbg->recoil_mode = R_DBG_RECOIL_NONE;
	return true;
}

/*
 * replace breakpoints before we continue execution
 *
 * this is called from r_debug_step_hard or r_debug_continue_kill
 *
 * this is a trick process because of breakpoints/tracepoints.
 *
 * if a breakpoint was just hit, we need step over that instruction before
 * allowing the caller to proceed as desired.
 *
 * if the user wants to step, the single step here does the job.
 */
static bool r_debug_recoil(RDebug *dbg, RDebugRecoilMode rc_mode) {
	/* if bp_addr is not set, we must not have actually hit a breakpoint */
	if (!dbg->reason.bp_addr) {
		return r_debug_bps_enable (dbg);
	}

	/* don't do anything if we already are recoiling */
	if (dbg->recoil_mode != R_DBG_RECOIL_NONE) {
		/* the first time recoil is called with swstep, we just need to
		 * look up the bp and step past it.
		 * the second time it's called, the new sw breakpoint should exist
		 * so we just restore all except what we originally hit and reset.
		 */
		if (dbg->swstep) {
			if (!r_bp_restore_except (dbg->bp, true, dbg->reason.bp_addr)) {
				return false;
			}
			return true;
		}

		/* otherwise, avoid recursion */
		return true;
	}

	/* we have entered recoil! */
	dbg->recoil_mode = rc_mode;

	/* step over the place with the breakpoint and let the caller resume */
	if (r_debug_step (dbg, 1) != 1) {
		return false;
	}

	/* when stepping away from a breakpoint during recoil in stepping mode,
	 * the r_debug_bp_hit function tells us that it was called
	 * innapropriately by setting bp_addr back to zero. however, recoil_mode
	 * is still set. we use this condition to know not to proceed but
	 * pretend as if we had.
	 */
	if (!dbg->reason.bp_addr && dbg->recoil_mode == R_DBG_RECOIL_STEP) {
		return true;
	}
	dbg->reason.bp_addr = 0;

	return r_debug_bps_enable (dbg);
}

/* add a breakpoint with some typical values */
R_API RBreakpointItem *r_debug_bp_add(RDebug *dbg, ut64 addr, int hw, bool watch, int rw, char *module, st64 m_delta) {
	int bpsz = r_bp_size(dbg->bp);
	RBreakpointItem *bpi;
	char *module_name = module? strdup (module): NULL;
	RListIter *iter;
	RDebugMap *map;
	if (!addr && module) {
		bool detect_module, valid = false;
		int perm;

		if (m_delta) {
			detect_module = false;
			RList *list = r_debug_modules_list (dbg);
			r_list_foreach (list, iter, map) {
				if (map->file && strstr (map->file, module)) {
					addr = map->addr + m_delta;
					free (module_name);
					module_name = strdup (map->file);
					break;
				}
			}
			r_list_free (list);
		} else {
			// module holds the address
			addr = (ut64)r_num_math (dbg->num, module);
			if (!addr) {
				return NULL;
			}
			detect_module = true;
		}
		r_debug_map_sync (dbg);
		r_list_foreach (dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				valid = true;
				if (detect_module && map->file) {
					free (module_name);
					module_name = strdup (map->file);
					m_delta = addr - map->addr;
				}
				perm = ((map->perm & 1) << 2) | (map->perm & 2) | ((map->perm & 4) >> 2);
				if (!(perm & R_BP_PROT_EXEC)) {
					R_LOG_WARN ("setting bp within mapped memory without exec perm");
				}
				break;
			}
		}
		if (!valid) {
			R_LOG_WARN ("module's base addr + delta is not a valid address");
			free (module_name);
			return NULL;
		}
	}
	if (!module) {
		//express db breakpoints as dbm due to ASLR when saving into project
		r_debug_map_sync (dbg);
		r_list_foreach (dbg->maps, iter, map) {
			if (map->file && addr >= map->addr && addr < map->addr_end) {
				free (module_name);
				module_name = strdup (map->file);
				m_delta = addr - map->addr;
				break;
			}
		}
	}
	if (watch) {
		hw = 1; // XXX
		bpi = r_bp_watch_add (dbg->bp, addr, bpsz, hw, rw);
	} else {
		bpi = hw
			? r_bp_add_hw (dbg->bp, addr, bpsz, R_BP_PROT_EXEC)
			: r_bp_add_sw (dbg->bp, addr, bpsz, R_BP_PROT_EXEC);
	}
	if (bpi) {
		if (module_name) {
			bpi->module_name = strdup (module_name);
			bpi->name = r_str_newf ("%s+0x%" PFMT64x, module_name, m_delta);
			R_FREE (module_name);
		}
		bpi->module_delta = m_delta;
	}
	free (module_name);
	return bpi;
}

static const char *r_debug_str_callback(RNum *userptr, ut64 off, int *ok) {
	// RDebug *dbg = (RDebug *)userptr;
	// TODO: implement the rnum callback for str or just get rid of it as we dont need it
	return NULL;
}

static ut64 r_debug_num_callback(RNum *userptr, const char *str, int *ok) {
	RDebug *dbg = (RDebug *)userptr;
	// resolve using regnu
	return r_debug_reg_get_err (dbg, str, ok, NULL);
}

R_API RDebug *r_debug_new(int hard) {
	RDebug *dbg = R_NEW0 (RDebug);
	if (!dbg) {
		return NULL;
	}
	// R_SYS_ARCH
	dbg->arch = strdup (R_SYS_ARCH);
	dbg->bits = R_SYS_BITS;
	dbg->trace_forks = 1;
	dbg->forked_pid = -1;
	dbg->main_pid = -1;
	dbg->n_threads = 0;
	dbg->trace_clone = 0;
	dbg->egg = NULL; // r_egg_new ();
	// r_egg_setup (dbg->egg, R_SYS_ARCH, R_SYS_BITS, R_SYS_ENDIAN, R_SYS_OS);
	dbg->trace_aftersyscall = true;
	dbg->follow_child = false;
	R_FREE (dbg->btalgo);
	dbg->trace_execs = 0;
	dbg->anal = NULL;
	dbg->pid = -1;
	dbg->snaps = r_list_newf ((RListFree)r_debug_snap_free);
	dbg->bpsize = 1;
	dbg->tid = -1;
	dbg->tree = r_tree_new ();
	dbg->tracenodes = sdb_new0 ();
	dbg->swstep = 0;
	dbg->stop_all_threads = false;
	dbg->trace = r_debug_trace_new ();
	dbg->cb_printf = (void *)printf;
	dbg->reg = r_reg_new ();
	dbg->num = r_num_new (r_debug_num_callback, r_debug_str_callback, dbg);
	dbg->current = NULL;
	dbg->threads = NULL;
	dbg->hitinfo = 1;
	/* TODO: needs a redesign? */
	dbg->maps = r_debug_map_list_new ();
	dbg->maps_user = r_debug_map_list_new ();
	dbg->q_regs = NULL;
	dbg->call_frames = NULL;
	dbg->main_arena_resolved = false;
	dbg->glibc_version_resolved = false;
	dbg->glibc_version = 231; /* default version ubuntu 20 */
	dbg->glibc_version_d = 0; /* no default glibc version */
	r_debug_signal_init (dbg);
	if (hard) {
		dbg->bp = r_bp_new ();
		r_debug_init_plugins (dbg);
		dbg->bp->iob.init = false;
		dbg->bp->baddr = 0;
	}
	return dbg;
}

static int free_tracenodes_entry(RDebug *dbg, const char *k, const char *v) {
	ut64 v_num = r_num_get (NULL, v);
	free ((void *)(size_t)v_num);
	return true;
}

R_API void r_debug_tracenodes_reset(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	sdb_foreach (dbg->tracenodes, (SdbForeachCallback)free_tracenodes_entry, dbg);
	sdb_reset (dbg->tracenodes);
}

R_API void r_debug_free(RDebug *dbg) {
	if (dbg) {
		// TODO: free it correctly.. we must ensure this is an instance and not a reference..
		r_bp_free (dbg->bp);
		//r_reg_free(&dbg->reg);
		free (dbg->snap_path);
		r_list_free (dbg->maps);
		r_list_free (dbg->maps_user);
		r_list_free (dbg->threads);
		r_num_free (dbg->num);
		r_tree_free (dbg->tree);
		sdb_foreach (dbg->tracenodes, (SdbForeachCallback)free_tracenodes_entry, dbg);
		sdb_free (dbg->tracenodes);
		r_debug_fini_plugins (dbg);
		r_list_free (dbg->call_frames);
		free (dbg->btalgo);
		r_debug_signal_fini (dbg);
		r_debug_trace_free (dbg->trace);
		r_list_free (dbg->snaps);
		r_debug_session_free (dbg->session);
		r_anal_op_free (dbg->cur_op);
		dbg->trace = NULL;
		// we dont own the egg now
		// r_egg_free (dbg->egg);
		free (dbg->arch);
		free (dbg->glob_libs);
		free (dbg->glob_unlibs);
		free (dbg);
	}
}

R_API bool r_debug_attach(RDebug *dbg, int pid) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	if (pid < 0) {
		return false;
	}
	bool ret = false;
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->attach) {
		ret = plugin->attach (dbg, pid);
		if (ret) {
			dbg->pid = pid;
			dbg->tid = pid;
			// dbg->pid = pid;
			// r_debug_select (dbg, pid, ret);
			r_debug_select (dbg, dbg->pid, dbg->tid);
		}
	}
	dbg->reason.type = R_DEBUG_REASON_STOPPED;
	return ret;
}

/* stop execution of child process */
R_API bool r_debug_stop(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin->stop) {
		return plugin->stop (dbg);
	}
	return false;
}

R_API bool r_debug_set_arch(RDebug *dbg, const char *arch, int bits) {
	R_RETURN_VAL_IF_FAIL (dbg && arch, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (!plugin) {
		return false;
	}
	switch (bits) {
	case 16:
		if (R_SYS_BITS_CHECK (plugin->bits, 16)) {
			dbg->bits = R_SYS_BITS_PACK (16);
		}
		break;
	case 27:
		if (R_SYS_BITS_CHECK (plugin->bits, 27)) {
			dbg->bits = R_SYS_BITS_PACK (27);
		}
		break;
	case 32:
		if (R_SYS_BITS_CHECK (plugin->bits, 32)) {
			dbg->bits = R_SYS_BITS_PACK (32);
		}
		break;
	case 64:
		dbg->bits = R_SYS_BITS_PACK (64);
		break;
	}
	if (plugin->bits) {
		if (R_SYS_BITS_CHECK (plugin->bits, bits)) {
			dbg->bits = R_SYS_BITS_PACK (bits);
		}
	}
	free (dbg->arch);
	dbg->arch = strdup (arch);
	return true;
}

/* Inject and execute shellcode
 * If restore is enabled, save the program state, including 4k on the stack.
 * This can be disabled with ignore_stack. Enabling this option results in only
 * registers being restored. It has no effect if restore is not enabled.
 *
 * The bytes overwritten at the program counter are always restored.
 *
 * TODO: Add support for reverse stack architectures
 *
 * XXX: This function will advance your seek to the end of the injected code.
 */
#define USEBP false
R_API bool r_debug_execute(RDebug *dbg, const ut8 *buf, int len, R_OUT ut64 *ret, bool restore, bool ignore_stack) {
	R_RETURN_VAL_IF_FAIL (dbg && buf && len > 0, false);
	ut8 stack_backup[1024];

	if (r_debug_is_dead (dbg)) {
		R_LOG_WARN ("Child is dead");
		return false;
	}
#if 0
	if (restore && !ignore_stack) {
		R_LOG_ERROR ("r_debug_execute: Cannot get stack pointer");
		return false;
	}
#endif
	if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
		R_LOG_ERROR ("Cannot sync registers");
		return false;
	}
	r_reg_arena_push (dbg->reg);
	ut64 reg_pc = r_reg_getv (dbg->reg, "PC");
	ut64 reg_sp = r_reg_getv (dbg->reg, "SP");
	if (reg_pc == UT64_MAX || reg_sp == UT64_MAX || !reg_pc || !reg_sp) {
		R_LOG_ERROR ("Invalid pc/sp values");
		return false;
	}

	ut8 *pc_backup = calloc (1, len);
	if (!pc_backup) {
		return false;
	}

	/* Store bytes at PC */
	dbg->iob.read_at (dbg->iob.io, reg_pc, pc_backup, len);
	if (restore && !ignore_stack) {
		/* Store bytes at stack */
		dbg->iob.read_at (dbg->iob.io, reg_sp, stack_backup, sizeof (stack_backup));
	}
#if USEBP
	ut64 bp_addr = reg_pc + len;
	r_bp_add_sw (dbg->bp, bp_addr, dbg->bpsize, R_BP_PROT_EXEC);
#endif
	// ut64 v = r_reg_setv (dbg->reg, "PC", reg_pc);
	dbg->iob.write_at (dbg->iob.io, reg_pc, buf, len);
	if (ret) {
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			R_LOG_WARN ("Cannot read registers after executing the injected payload");
		}
		*ret = r_reg_getv (dbg->reg, "PC");
	}
#if 1
	r_debug_step (dbg, 1);
#else
	r_debug_continue (dbg);
#endif
	if (dbg->coreb.core) {
		ut64 v = r_reg_getv (dbg->reg, "rax");
		dbg->coreb.cmdf (dbg->coreb.core, "'f dx.value=0x%08"PFMT64x, v);
		R_LOG_INFO ("'f dx.value = 0x%08"PFMT64x, v);
	}
#if USEBP
	/* Restore bytes at PC and remove the breakpoint reference */
	r_bp_del (dbg->bp, bp_addr);
#endif
	/* Propagate return value */
	if (!ignore_stack && reg_sp) {
		/* Restore stack */
		// eprintf ("WRITE STEACK 0x%llx\n", reg_sp);
		dbg->iob.write_at (dbg->iob.io, reg_sp, stack_backup, 4096);
	}
	if (ret) {
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			R_LOG_WARN ("Cannot read registers after executing the injected payload");
		}
		*ret = r_reg_getv (dbg->reg, "PC");
	}
	// eprintf ("WRITE CODE 0x%llx\n", reg_pc);
	dbg->iob.write_at (dbg->iob.io, reg_pc, pc_backup, len);
	if (restore) {
		r_reg_arena_pop (dbg->reg);
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, true)) {
			R_LOG_ERROR ("Cannot restore registers");
		}
	}

	free (pc_backup);

	return true;
}

R_API bool r_debug_startv(struct r_debug_t *dbg, int argc, char **argv) {
	/* TODO : r_debug_startv unimplemented */
	return false;
}

R_API bool r_debug_start(RDebug *dbg, const char *cmd) {
	/* TODO: this argc/argv parser is done in r_io */
	// TODO: parse cmd and generate argc and argv
	return false;
}

R_API bool r_debug_detach(RDebug *dbg, int pid) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	bool ret = false;
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->detach) {
		ret = -plugin->detach (dbg, pid);
		if (dbg->pid == pid) {
			dbg->pid = -1;
			dbg->tid = -1;
		}
	}
	return ret;
}

R_API bool r_debug_select(RDebug *dbg, int pid, int tid) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	if (pid < 0) {
		return false;
	}
	if (tid < 0) {
		tid = pid;
	}
#if 0
	pid = r_io_desc_get_pid (dbg->iob.io->desc);
	tid = r_io_desc_get_tid (dbg->iob.io->desc);
#endif
	if (pid == -1 && tid == -1) {
		if (dbg->pid != -1) {
			R_LOG_ERROR ("Child %d is dead", dbg->pid);
		}
	}
	if (pid < 0 || tid < 0) {
		return false;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->select) {
		if (!plugin->select (dbg, pid, tid)) {
			return false;
		}
	}
	dbg->pid = pid;
	dbg->tid = tid;
	if (dbg->pid != -1) {
		char *pidcmd = r_str_newf ("pid %d", dbg->pid);
		if (pidcmd) {
			free (r_io_system (dbg->iob.io, pidcmd));
			free (pidcmd);
		}
	} else {
		R_LOG_ERROR ("Cannot find pid for child %d", dbg->pid);
	}

	// Synchronize with the current thread's data
	if (dbg->coreb.core) {
		RCore *core = (RCore *)dbg->coreb.core;

		r_reg_arena_swap (core->dbg->reg, true);
		r_debug_reg_sync (dbg, R_REG_TYPE_ALL, false);

		core->offset = r_debug_reg_get (dbg, "PC");
	}

	return true;
}

// TODO type should be enum so we can ensure to not miss an item
R_API const char *r_debug_reason_tostring(int type) {
	switch (type) {
	case R_DEBUG_REASON_ABORT: return "abort";
	case R_DEBUG_REASON_BREAKPOINT: return "breakpoint";
	case R_DEBUG_REASON_DEAD: return "dead";
	case R_DEBUG_REASON_DIVBYZERO: return "div-by-zero";
	case R_DEBUG_REASON_ERROR: return "error";
	case R_DEBUG_REASON_EXIT_LIB: return "exit-lib";
	case R_DEBUG_REASON_EXIT_PID: return "exit-pid";
	case R_DEBUG_REASON_EXIT_TID: return "exit-tid";
	case R_DEBUG_REASON_FPU: return "fpu";
	case R_DEBUG_REASON_ILLEGAL: return "illegal";
	case R_DEBUG_REASON_INT: return "interrupt";
	case R_DEBUG_REASON_NEW_LIB: return "new-lib";
	case R_DEBUG_REASON_NEW_PID: return "new-pid";
	case R_DEBUG_REASON_NEW_TID: return "new-tid";
	case R_DEBUG_REASON_NONE: return "none";
	case R_DEBUG_REASON_READERR: return "read-error";
	case R_DEBUG_REASON_SEGFAULT: return "segfault";
	case R_DEBUG_REASON_SIGNAL: return "signal";
	case R_DEBUG_REASON_STEP: return "step";
	case R_DEBUG_REASON_STOPPED: return "stopped";
	case R_DEBUG_REASON_SWI: return "software-interrupt";
	case R_DEBUG_REASON_TRACEPOINT: return "tracepoint";
	case R_DEBUG_REASON_TRAP: return "trap";
	case R_DEBUG_REASON_UNKNOWN: return "unknown";
	case R_DEBUG_REASON_USERSUSP: return "suspended-by-user";
	case R_DEBUG_REASON_WRITERR: return "write-error";
	}
	return "unhandled";
}

R_API RDebugReasonType r_debug_stop_reason(RDebug *dbg) {
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// return dbg->reason
	return dbg->reason.type;
}

/*
 * wait for an event to happen on the selected pid/tid
 *
 * Returns  R_DEBUG_REASON_*
 */
R_API RDebugReasonType r_debug_wait(RDebug *dbg, R_NULLABLE RBreakpointItem **bp) {
	R_RETURN_VAL_IF_FAIL (dbg, R_DEBUG_REASON_ERROR);
	RDebugReasonType reason = R_DEBUG_REASON_ERROR;
	if (!dbg) {
		return reason;
	}
	if (bp) {
		*bp = NULL;
	}
	/* default to unknown */
	dbg->reason.type = R_DEBUG_REASON_UNKNOWN;
	if (r_debug_is_dead (dbg)) {
		return R_DEBUG_REASON_DEAD;
	}

	/* if our debugger plugin has wait */
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->wait) {
		reason = plugin->wait (dbg, dbg->pid);
		if (reason == R_DEBUG_REASON_DEAD) {
			R_LOG_INFO ("==> Process finished");
			REventDebugProcessFinished event = {
				.pid = dbg->pid
			};
			r_event_send (dbg->ev, R_EVENT_DEBUG_PROCESS_FINISHED, &event);
			// XXX(jjd): TODO: handle fallback or something else
			//r_debug_select (dbg, -1, -1);
			return R_DEBUG_REASON_DEAD;
		}
#if __linux__
		// Letting other threads running will cause ptrace commands to fail
		// when writing to the same process memory to set/unset breakpoints
		// and is problematic in Linux.
		if (dbg->continue_all_threads) {
			r_debug_stop (dbg);
		}
#endif
		/* propagate errors from the plugin */
		if (reason == R_DEBUG_REASON_ERROR) {
			return R_DEBUG_REASON_ERROR;
		}

		/* read general purpose registers */
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			return R_DEBUG_REASON_ERROR;
		}

		bool libs_bp = (dbg->glob_libs || dbg->glob_unlibs) ? true : false;
		/* if the underlying stop reason is a breakpoint, call the handlers */
		if (reason == R_DEBUG_REASON_BREAKPOINT ||
			reason == R_DEBUG_REASON_STEP ||
			(libs_bp && ((reason == R_DEBUG_REASON_NEW_LIB) || (reason == R_DEBUG_REASON_EXIT_LIB)))) {
			RRegItem *pc_ri;
			RBreakpointItem *b = NULL;
			ut64 pc;

			/* get the program coounter */
			pc_ri = r_reg_get (dbg->reg, "PC", -1);
			if (!pc_ri) { /* couldn't find PC?! */
				R_LOG_ERROR ("Couldn't find the program counter!");
				return R_DEBUG_REASON_ERROR;
			}

			/* get the value */
			pc = r_reg_get_value (dbg->reg, pc_ri);

			if (!r_debug_bp_hit (dbg, pc_ri, pc, &b)) {
				return R_DEBUG_REASON_ERROR;
			}

			if (bp) {
				*bp = b;
			}

			if (b && reason == R_DEBUG_REASON_STEP) {
				reason = R_DEBUG_REASON_BREAKPOINT;
			}
			/* if we hit a tracing breakpoint, we need to continue in
			 * whatever mode the user desired. */
			if (dbg->coreb.core && b && b->cond) {
				reason = R_DEBUG_REASON_COND;
			}
			if (b && b->trace) {
				reason = R_DEBUG_REASON_TRACEPOINT;
			}
		}

		dbg->reason.type = reason;
		if (reason == R_DEBUG_REASON_SIGNAL && dbg->reason.signum != -1) {
			/* handle signal on continuations here */
			int what = r_debug_signal_what (dbg, dbg->reason.signum);
			const char *name = r_signal_tostring (dbg->reason.signum);
			const char *humn = r_signal_to_human (dbg->reason.signum);
			if (name && strcmp ("SIGTRAP", name)) {
				r_cons_printf ("[+] signal %d aka %s received %d (%s)\n",
						dbg->reason.signum, name, what, humn);
			}
		}
	}
	return reason;
}

R_API bool r_debug_step_soft(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	ut8 buf[32];
	ut64 pc, sp, r;
	ut64 next[2];
	RAnalOp op;
	int br, i;
	union {
		ut64 r64;
		ut32 r32[2];
	} sp_top;
	union {
		ut64 r64;
		ut32 r32[2];
	} memval;

	if (dbg->recoil_mode == R_DBG_RECOIL_NONE) {
		dbg->recoil_mode = R_DBG_RECOIL_STEP;
	}

	if (r_debug_is_dead (dbg)) {
		return false;
	}

	pc = r_debug_reg_get (dbg, "PC");
	sp = r_debug_reg_get (dbg, "SP");

	if (!dbg->iob.read_at) {
		return false;
	}
	if (!dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf))) {
		return false;
	}
	if (!r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC)) {
		return false;
	}
	if (op.type == R_ANAL_OP_TYPE_ILL) {
		return false;
	}
	switch (op.type) {
	case R_ANAL_OP_TYPE_RET:
		dbg->iob.read_at (dbg->iob.io, sp, (ut8 *)&sp_top, 8);
		next[0] = R_SYS_BITS_CHECK (dbg->bits, 64) ? sp_top.r64 : sp_top.r32[0];
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
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_RCALL:
		r = r_debug_reg_get (dbg,op.reg);
		next[0] = r;
		br = 1;
		break;
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_IRJMP:
		r = r_debug_reg_get (dbg,op.reg);
		if (!dbg->iob.read_at (dbg->iob.io, r, (ut8*)&memval, 8)) {
			next[0] = op.addr + op.size;
		} else {
			next[0] = R_SYS_BITS_CHECK (dbg->bits, 64) ? memval.r64 : memval.r32[0];
		}
		br = 1;
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_MJMP:
		if (op.ireg) {
			r = r_debug_reg_get (dbg,op.ireg);
		} else {
			r = 0;
		}
		if (!dbg->iob.read_at (dbg->iob.io, r*op.scale + op.disp, (ut8*)&memval, 8)) {
			next[0] = op.addr + op.size;
		} else {
			next[0] = R_SYS_BITS_CHECK (dbg->bits, 64) ? memval.r64: memval.r32[0];
		}
		br = 1;
		break;
	case R_ANAL_OP_TYPE_UJMP:
	default:
		next[0] = op.addr + op.size;
		br = 1;
		break;
	}

	for (i = 0; i < br; i++) {
		RBreakpointItem *bpi = r_bp_add_sw (dbg->bp, next[i], dbg->bpsize, R_BP_PROT_EXEC);
		if (bpi) {
			bpi->swstep = true;
		}
	}
	// XXX this causes an stack exhaustion problem so it should be done by the caller
	bool ret = r_debug_continue (dbg);

	for (i = 0; i < br; i++) {
		r_bp_del (dbg->bp, next[i]);
	}

	return ret;
}

R_API bool r_debug_step_hard(RDebug *dbg, RBreakpointItem **pb) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugReasonType reason;

	dbg->reason.type = R_DEBUG_REASON_STEP;
	if (r_debug_is_dead (dbg)) {
		return false;
	}

	/* only handle recoils when not already in recoil mode. */
	if (dbg->recoil_mode == R_DBG_RECOIL_NONE) {
		/* handle the stage-2 of breakpoints */
		if (!r_debug_recoil (dbg, R_DBG_RECOIL_STEP)) {
			return false;
		}

		/* recoil already stepped once, so we don't step again. */
		if (dbg->recoil_mode == R_DBG_RECOIL_STEP) {
			dbg->recoil_mode = R_DBG_RECOIL_NONE;
			return true;
		}
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && !plugin->step (dbg)) {
		return false;
	}

#if __linux__
	// Turn off continue_all_threads to make sure linux_dbg_wait
	// only waits for one target for a single-step or breakpoint trap
	bool prev_continue = dbg->continue_all_threads;
	dbg->continue_all_threads = false;
#endif
	reason = r_debug_wait (dbg, pb);
#if __linux__
	dbg->continue_all_threads = prev_continue;
#endif

	if (reason == R_DEBUG_REASON_DEAD || r_debug_is_dead (dbg)) {
		return false;
	}
	// Unset breakpoints before leaving
	if (reason != R_DEBUG_REASON_BREAKPOINT &&
		reason != R_DEBUG_REASON_COND &&
		reason != R_DEBUG_REASON_TRACEPOINT) {
		r_bp_restore (dbg->bp, false);
	}
	/* TODO: handle better */
	if (reason == R_DEBUG_REASON_ERROR) {
		return false;
	}
	return true;
}

R_API int r_debug_step(RDebug *dbg, int steps) {
	R_RETURN_VAL_IF_FAIL (dbg, 0);
	RBreakpointItem *bp = NULL;
	int ret, steps_taken = 0;

	/* who calls this without giving a positive number? */
	if (steps < 1) {
		steps = 1;
	}

	if (r_debug_is_dead (dbg)) {
		return steps_taken;
	}

	// R2_590 - add a var in RDebug.esil_step_cmd instead of pulling config on every stel
	const char *cmd_step = dbg->coreb.cfgGet (dbg->coreb.core, "cmd.step");
	if (R_STR_ISEMPTY (cmd_step)) {
		cmd_step = NULL;
	}
	dbg->reason.type = R_DEBUG_REASON_STEP;

	if (dbg->session) {
		if (dbg->session->cnum != dbg->session->maxcnum) {
			steps_taken = r_debug_step_cnum (dbg, steps);
		}
	}

	for (; steps_taken < steps; steps_taken++) {
		if (dbg->session && dbg->recoil_mode == R_DBG_RECOIL_NONE) {
			dbg->session->cnum++;
			dbg->session->maxcnum++;
			dbg->session->bp = 0;
			if (!r_debug_trace_ins_before (dbg)) {
				R_LOG_ERROR ("trace_ins_before: failed");
			}
		}
		if (dbg->swstep) {
			ret = r_debug_step_soft (dbg);
		} else {
			ret = r_debug_step_hard (dbg, &bp);
		}
		if (cmd_step && dbg->coreb.cmd) {
			dbg->coreb.cmd (dbg->coreb.core, ".e cmd.step @r:PC");
		}
		if (!ret) {
			R_LOG_ERROR ("Stepping failed!");
			return steps_taken;
		}
		if (dbg->session && dbg->recoil_mode == R_DBG_RECOIL_NONE) {
			if (!r_debug_trace_ins_after (dbg)) {
				R_LOG_ERROR ("trace_ins_after: failed");
			}
			dbg->session->reasontype = dbg->reason.type;
			dbg->session->bp = bp;
		}
		dbg->steps++;
		dbg->reason.type = R_DEBUG_REASON_STEP;
	}

	return steps_taken;
}

static bool isStepOverable(ut64 opType) {
	switch (opType & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_SWI:
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
		return true;
	}
	return false;
}

R_API int r_debug_step_over(RDebug *dbg, int steps) {
	R_RETURN_VAL_IF_FAIL (dbg, -1);
	RAnalOp op;
	ut64 buf_pc, pc, ins_size;
	ut8 buf[DBG_BUF_SIZE];
	int steps_taken = 0;

	if (r_debug_is_dead (dbg)) {
		return steps_taken;
	}

	if (steps < 1) {
		steps = 1;
	}

	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->step_over) {
		for (; steps_taken < steps; steps_taken++) {
			if (dbg->session && dbg->recoil_mode == R_DBG_RECOIL_NONE) {
				dbg->session->cnum++;
				dbg->session->maxcnum++;
				r_debug_trace_ins_before (dbg);
			}
			if (!plugin->step_over (dbg)) {
				return steps_taken;
			}
			if (dbg->session && dbg->recoil_mode == R_DBG_RECOIL_NONE) {
				r_debug_trace_ins_after (dbg);
			}
		}
		return steps_taken;
	}

	if (!dbg->anal || !dbg->reg) {
		return steps_taken;
	}

	// Initial refill
	buf_pc = r_debug_reg_get (dbg, "PC");
	dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));

	for (; steps_taken < steps; steps_taken++) {
		pc = r_debug_reg_get (dbg, "PC");
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof (buf)) {
			buf_pc = pc;
			dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));
		}
		// Analyze the opcode
		if (!r_anal_op (dbg->anal, &op, pc, buf + (pc - buf_pc), sizeof (buf) - (pc - buf_pc), R_ARCH_OP_MASK_BASIC)) {
			R_LOG_ERROR ("debug-step-over: Decode error at %"PFMT64x, pc);
			return steps_taken;
		}
		if (op.fail == -1) {
			ins_size = pc + op.size;
		} else {
			// Use op.fail here instead of pc+op.size to enforce anal backends to fill in this field
			ins_size = op.fail;
		}
		// Skip over all the subroutine calls
		if (isStepOverable (op.type)) {
			if (!r_debug_continue_until (dbg, ins_size)) {
				R_LOG_ERROR ("Could not step over call @ 0x%"PFMT64x, pc);
				return steps_taken;
			}
		} else if ((op.prefix & (R_ANAL_OP_PREFIX_REP | R_ANAL_OP_PREFIX_REPNE | R_ANAL_OP_PREFIX_LOCK))) {
			//R_LOG_ERROR ("REP: skip to next instruction");
			if (!r_debug_continue_until (dbg, ins_size)) {
				R_LOG_ERROR ("step over failed over rep");
				return steps_taken;
			}
		} else {
			r_debug_step (dbg, 1);
		}
	}

	return steps_taken;
}

R_API bool r_debug_goto_cnum(RDebug *dbg, ut32 cnum) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	if (cnum > dbg->session->maxcnum) {
		R_LOG_ERROR ("out of cnum range");
		return false;
	}
	dbg->session->cnum = cnum;
	r_debug_session_restore_reg_mem (dbg, cnum);

	return true;
}

R_API int r_debug_step_back(RDebug *dbg, int steps) {
	R_RETURN_VAL_IF_FAIL (dbg, -1);
	if (steps > dbg->session->cnum) {
		steps = dbg->session->cnum;
	}
	if (!r_debug_goto_cnum (dbg, dbg->session->cnum - steps)) {
		return -1;
	}
	return steps;
}

R_API int r_debug_step_cnum(RDebug *dbg, int steps) {
	R_RETURN_VAL_IF_FAIL (dbg, -1);
	if (steps > dbg->session->maxcnum - dbg->session->cnum) {
		steps = dbg->session->maxcnum - dbg->session->cnum;
	}
	r_debug_goto_cnum (dbg, dbg->session->cnum + steps);
	return steps;
}

R_API int r_debug_continue_kill(RDebug *dbg, int sig) {
	R_RETURN_VAL_IF_FAIL (dbg, -1);
	RDebugReasonType reason = R_DEBUG_REASON_NONE;
	int ret = 0;
	RBreakpointItem *bp = NULL;

	if (!dbg) {
		return -1;
	}

	// If the debugger is not at the end of the changes
	// Go to the end or the next breakpoint in the changes
	if (dbg->session && dbg->session->cnum != dbg->session->maxcnum) {
		bool has_bp = false;
		RRegItem *ripc = r_reg_get (dbg->reg, "PC", R_REG_TYPE_GPR);
		RVector *vreg = ht_up_find (dbg->session->registers, ripc->offset | (ripc->arena << 16), NULL);
		RDebugChangeReg *reg;
		r_vector_foreach_prev (vreg, reg) {
			if (reg->cnum <= dbg->session->cnum) {
				continue;
			}
			has_bp = r_bp_get_in (dbg->bp, reg->data, R_BP_PROT_EXEC);
			if (has_bp) {
				R_LOG_INFO ("hit breakpoint at: 0x%" PFMT64x " cnum: %d", reg->data, reg->cnum);
				r_debug_goto_cnum (dbg, reg->cnum);
				return dbg->tid;
			}
		}

		r_debug_goto_cnum (dbg, dbg->session->maxcnum);
		return dbg->tid;
	}

repeat:
	if (r_debug_is_dead (dbg)) {
		return 0;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (dbg->session && dbg->trace_continue) {
		while (!r_cons_is_breaked ()) {
			if (r_debug_step (dbg, 1) != 1) {
				break;
			}
			if (dbg->session->reasontype != R_DEBUG_REASON_STEP) {
				break;
			}
		}
		reason = dbg->session->reasontype;
		bp = dbg->session->bp;
	} else if (plugin && plugin->cont) {
		/* handle the stage-2 of breakpoints */
		if (!r_debug_recoil (dbg, R_DBG_RECOIL_CONTINUE)) {
			return 0;
		}
		/* tell the inferior to go! */
		ret = plugin->cont (dbg, dbg->pid, dbg->tid, sig);
		//XXX(jjd): why? //dbg->reason.signum = 0;
		reason = r_debug_wait (dbg, &bp);
	} else {
		return 0;
	}

	if (dbg->coreb.core) {
		RCore *core = (RCore *)dbg->coreb.core;
		RNum *num = core->num;
		if (reason == R_DEBUG_REASON_COND) {
			if (bp && bp->cond && dbg->coreb.cmd) {
				dbg->coreb.cmd (dbg->coreb.core, bp->cond);
			}
			if (num->value) {
				goto repeat;
			}
		}
	}
	if (reason == R_DEBUG_REASON_BREAKPOINT &&
	   ((bp && !bp->enabled) || (!bp && !r_cons_is_breaked () && dbg->coreb.core &&
					dbg->coreb.cfgGetI (dbg->coreb.core, "dbg.bpsysign")))) {
		goto repeat;
	}

#if __linux__
	if (reason == R_DEBUG_REASON_NEW_PID && dbg->follow_child) {
#if DEBUGGER
		/// if the plugin is not compiled link fails, so better do runtime linking
		/// until this code gets fixed
		static bool (*linux_attach_new_process) (RDebug *dbg, int pid) = NULL;
		if (!linux_attach_new_process) {
			linux_attach_new_process = r_lib_dl_sym (NULL, "linux_attach_new_process");
		}
		if (linux_attach_new_process) {
			linux_attach_new_process (dbg, dbg->forked_pid);
		}
#endif
		goto repeat;
	}

	if (reason == R_DEBUG_REASON_NEW_TID) {
		ret = dbg->tid;
		if (!dbg->trace_clone) {
			goto repeat;
		}
	}

	if (reason == R_DEBUG_REASON_EXIT_TID) {
		goto repeat;
	}
#endif
	if (reason != R_DEBUG_REASON_DEAD) {
		ret = dbg->tid;
	}
#if R2__WINDOWS__
	if (reason == R_DEBUG_REASON_NEW_LIB ||
		reason == R_DEBUG_REASON_EXIT_LIB ||
		reason == R_DEBUG_REASON_NEW_TID ||
		reason == R_DEBUG_REASON_NONE ||
		reason == R_DEBUG_REASON_EXIT_TID ) {
		goto repeat;
	}
#endif
	if (reason == R_DEBUG_REASON_EXIT_PID) {
#if R2__WINDOWS__
		dbg->pid = -1;
#elif __linux__
		r_debug_bp_update (dbg);
		r_bp_restore (dbg->bp, false); // (vdf) there has got to be a better way
#endif
	}

	/* if continuing killed the inferior, we won't be able to get
	 * the registers.. */
	if (reason == R_DEBUG_REASON_DEAD || r_debug_is_dead (dbg)) {
		return 0;
	}

	/* if we hit a tracing breakpoint, we need to continue in
	 * whatever mode the user desired. */
	if (reason == R_DEBUG_REASON_TRACEPOINT) {
		r_debug_step (dbg, 1);
		goto repeat;
	}

	/* choose the thread that was returned from the continue function */
	// XXX(jjd): there must be a cleaner way to do this...
	if (ret != dbg->tid) {
		r_debug_select (dbg, dbg->pid, ret);
	}
	sig = 0; // clear continuation after signal if needed

	/* handle general signals here based on the return from the wait
	 * function */
	if (dbg->reason.signum != -1) {
		int what = r_debug_signal_what (dbg, dbg->reason.signum);
		if (what & R_DBG_SIGNAL_CONT) {
			sig = dbg->reason.signum;
			R_LOG_INFO ("Continue into the signal %d handler", sig);
			goto repeat;
		} else if (what & R_DBG_SIGNAL_SKIP) {
			// skip signal. requires skipping one instruction
			ut8 buf[64];
			RAnalOp op = {0};
			ut64 pc = r_debug_reg_get (dbg, "PC");
			dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
			r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
			if (op.size > 0) {
				const char *signame = r_signal_tostring (dbg->reason.signum);
				r_debug_reg_set (dbg, "PC", pc+op.size);
				R_LOG_INFO ("Skip signal %d handler %s",
					dbg->reason.signum, signame);
				goto repeat;
			} else {
				ut64 pc = r_debug_reg_get (dbg, "PC");
				R_LOG_INFO ("Stalled with an exception at 0x%08"PFMT64x, pc);
			}
		}
	}
#if R2__WINDOWS__
	r_cons_break_pop ();
#endif

	// Unset breakpoints before leaving
	if (reason != R_DEBUG_REASON_BREAKPOINT) {
		r_bp_restore (dbg->bp, false);
	}

	// Add a checkpoint at stops
	if (dbg->session && !dbg->trace_continue) {
		dbg->session->cnum++;
		dbg->session->maxcnum++;
		r_debug_add_checkpoint (dbg);
	}

	return ret;
}

R_API int r_debug_continue(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, -1);
	return r_debug_continue_kill (dbg, 0);
}

R_API int r_debug_continue_with_signal(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, -1);
#if R2__WINDOWS__
	return r_debug_continue_kill (dbg, DBG_EXCEPTION_NOT_HANDLED);
#else
	return r_debug_continue_kill (dbg, dbg->reason.signum);
#endif
}

R_API bool r_debug_continue_until_nontraced(RDebug *dbg) {
	R_LOG_TODO ("not implemented");
	return false;
}

R_API bool r_debug_continue_until_optype(RDebug *dbg, int type, bool over) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	int n = 0;
	RAnalOp op;
	ut8 buf[DBG_BUF_SIZE];

	if (r_debug_is_dead (dbg)) {
		return false;
	}

	if (!dbg->anal || !dbg->reg) {
		R_LOG_ERROR ("Undefined pointer at dbg->anal");
		return false;
	}

	r_debug_step (dbg, 1);
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);

	// Initial refill
	ut64 buf_pc = r_debug_reg_get (dbg, "PC");
	dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));

	// step first, we don't want to check current optype
	for (;;) {
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			break;
		}

		ut64 pc = r_debug_reg_get (dbg, "PC");
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof (buf)) {
			buf_pc = pc;
			dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));
		}
		// Analyze the opcode
		if (!r_anal_op (dbg->anal, &op, pc, buf + (pc - buf_pc), sizeof (buf) - (pc - buf_pc), R_ARCH_OP_MASK_BASIC)) {
			R_LOG_ERROR ("Decode error at %"PFMT64x, pc);
			return false;
		}
		if (op.type == type) {
			switch (type) {
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_UCALL:
				if (over) {
					r_debug_step_over (dbg, 1);
				}
				break;
			}
			break;
		}
		// Step over and repeat
		int ret = over
			? r_debug_step_over (dbg, 1)
			: r_debug_step (dbg, 1);

		if (!ret) {
			R_LOG_ERROR ("r_debug_step: failed");
			break;
		}
		n++;
	}
	return n;
}

static bool r_debug_continue_until_internal(RDebug *dbg, ut64 addr, bool block) {
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	// Check if there was another breakpoint set at addr
	bool has_bp = r_bp_get_in (dbg->bp, addr, R_BP_PROT_EXEC);
	if (!has_bp) {
		r_bp_add_sw (dbg->bp, addr, dbg->bpsize, R_BP_PROT_EXEC);
	}

	// Continue until the bp is reached
	dbg->reason.type = 0;
	for (;;) {
		if (r_debug_is_dead (dbg) || dbg->reason.type) {
			break;
		}
		ut64 pc = r_debug_reg_get (dbg, "PC");
		if (pc == addr) {
			break;
		}
		if (block && r_bp_get_at (dbg->bp, pc)) {
			break;
		}
		r_debug_continue (dbg);
	}
	// Clean up if needed
	if (!has_bp) {
		r_bp_del (dbg->bp, addr);
	}
	return true;
}

R_API bool r_debug_continue_until(RDebug *dbg, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	return r_debug_continue_until_internal (dbg, addr, true);
}

R_API bool r_debug_continue_until_nonblock(RDebug *dbg, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	return r_debug_continue_until_internal (dbg, addr, false);
}

R_API bool r_debug_continue_back(RDebug *dbg) {
	int cnum;
	bool has_bp = false;

	RRegItem *ripc = r_reg_get (dbg->reg, "PC", R_REG_TYPE_GPR);
	RVector *vreg = ht_up_find (dbg->session->registers, ripc->offset | (ripc->arena << 16), NULL);
	if (!vreg) {
		R_LOG_ERROR ("cannot find PC change vector");
		return false;
	}
	RDebugChangeReg *reg;
	r_vector_foreach_prev (vreg, reg) {
		if (reg->cnum >= dbg->session->cnum) {
			continue;
		}
		has_bp = r_bp_get_in (dbg->bp, reg->data, R_BP_PROT_EXEC);
		if (has_bp) {
			cnum = reg->cnum;
			R_LOG_INFO ("hit breakpoint at: 0x%" PFMT64x " cnum: %d", reg->data, reg->cnum);
			break;
		}
	}

	if (has_bp) {
		r_debug_goto_cnum (dbg, cnum);
	} else {
		if (dbg->session->maxcnum > 0) {
			r_debug_goto_cnum (dbg, 0);
		}
	}

	return true;
}

static int show_syscall(RDebug *dbg, const char *sysreg) {
	const char *sysname;
	char regname[32];
	int reg, i, args;
	RSyscallItem *si;
	reg = (int)r_debug_reg_get (dbg, sysreg);
	si = r_syscall_get (dbg->anal->syscall, reg, -1);
	if (si) {
		sysname = r_str_get_fail (si->name, "unknown");
		args = si->args;
	} else {
		sysname = "unknown";
		args = 3;
	}
	RStrBuf *sb = r_strbuf_newf ("--> %s 0x%08"PFMT64x" syscall %d %s (", sysreg,
			r_debug_reg_get (dbg, "PC"), reg, sysname);
	for (i = 0; i < args; i++) {
		snprintf (regname, sizeof (regname) - 1, "A%d", i);
		ut64 val = r_debug_reg_get (dbg, regname);
		if (((st64)val < 0) && ((st64)val>-0xffff)) {
			r_strbuf_appendf (sb, "%"PFMT64d"%s", val, (i+1==args)?"":" ");
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x"%s", val, (i+1==args)?"":" ");
		}
	}
	r_strbuf_append (sb, ")\n");
	char *s = r_strbuf_drain (sb);
	R_LOG_INFO ("%s", s);
	free (s);
	r_syscall_item_free (si);
	return reg;
}

// continue execution until a syscall is found, then return its syscall number or -1 on error
R_API int r_debug_continue_syscalls(RDebug *dbg, int *sc, int n_sc) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	int i, err, reg;
	if (!dbg->current || r_debug_is_dead (dbg)) {
		return -1;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && !plugin->contsc) {
		/* user-level syscall tracing */
		r_debug_continue_until_optype (dbg, R_ANAL_OP_TYPE_SWI, 0);
		return show_syscall (dbg, "A0");
	}

	if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
		R_LOG_ERROR ("--> cannot read registers");
		return -1;
	}
	reg = (int)r_debug_reg_get_err (dbg, "SN", &err, NULL);
	if (err) {
		R_LOG_ERROR ("Cannot find 'sn' register for current arch-os");
		return -1;
	}
	for (;;) {
		RDebugReasonType reason;

		if (r_cons_singleton ()->context->breaked) {
			break;
		}
#if __linux__
		// step is needed to avoid dupped contsc results
		/* XXX(jjd): actually one stop is before the syscall, the other is
		 * after.  this allows you to inspect the arguments before and the
		 * return value after... */
		r_debug_step (dbg, 1);
#endif
		r_debug_contsc (dbg, 0); // TODO handle return value
		// wait until continuation
		reason = r_debug_wait (dbg, NULL);
		if (reason == R_DEBUG_REASON_DEAD || r_debug_is_dead (dbg)) {
			break;
		}
#if 0
		if (reason != R_DEBUG_REASON_STEP) {
			R_LOG_INFO ("astep");
			break;
		}
#endif
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			R_LOG_ERROR ("cannot sync regs, process is probably dead");
			return -1;
		}
		reg = show_syscall (dbg, "SN");

		if (dbg->coreb.core && dbg->coreb.sysHit) {
			dbg->coreb.sysHit (dbg->coreb.core);
		}

		if (n_sc == -1) {
			continue;
		}
		if (n_sc == 0) {
			break;
		}
		for (i = 0; i < n_sc; i++) {
			if (sc[i] == reg) {
				return reg;
			}
		}
		// TODO: must use r_core_cmd(as)..import code from rcore
	}
	return -1;
}

R_API int r_debug_continue_syscall(RDebug *dbg, int sc) {
	return r_debug_continue_syscalls (dbg, &sc, 1);
}

// TODO: bad name, contsc wtf
R_API bool r_debug_contsc(RDebug *dbg, int num) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	bool ret = true; // false?
	if (plugin && plugin->contsc) {
		ret = plugin->contsc (dbg, dbg->pid, num);
	}
	R_LOG_TODO ("show syscall information");
	/* r2rc task? ala inject? */
	return ret;
}

R_API bool r_debug_kill(RDebug *dbg, int pid, int tid, int sig) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->kill) {
		if (pid > 0) {
			return plugin->kill (dbg, pid, tid, sig);
		}
		return -1;
	}
	R_LOG_WARN ("this debugger backend does not implement kill");
	return false;
}

R_API RList *r_debug_frames(RDebug *dbg, ut64 at) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->frames) {
		return plugin->frames (dbg, at);
	}
	return NULL;
}

/* TODO: Implement fork and clone */
R_API int r_debug_child_fork(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	// if (dbg && dbg->current && dbg->current->plugin.frames)
	// return dbg->current->plugin.frames (dbg);
	return 0;
}

R_API int r_debug_child_clone(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	// if (dbg && dbg->current && dbg->current->plugin.frames)
	// return dbg->current->plugin.frames (dbg);
	return 0;
}

R_API bool r_debug_is_dead(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (!plugin) {
		return false;
	}
	// workaround for debug.io.. should be generic
	if (!strcmp (plugin->meta.name, "io")) {
		return false;
	}
	bool is_dead = (dbg->pid < 0 && strncmp (plugin->meta.name, "gdb", 3)) || (dbg->reason.type == R_DEBUG_REASON_DEAD);
	if (dbg->pid > 0 && plugin && plugin->kill) {
		is_dead = !plugin->kill (dbg, dbg->pid, false, 0);
	}
#if 0
	if (!is_dead && dbg->current && dbg->current->plugin.kill) {
		is_dead = !dbg->current->plugin.kill (dbg, dbg->pid, false, 0);
	}
#endif
	if (is_dead) {
		dbg->reason.type = R_DEBUG_REASON_DEAD;
	}
	return is_dead;
}

R_API bool r_debug_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->map_protect) {
		return plugin->map_protect (dbg, addr, size, perms);
	}
	return false;
}

R_API void r_debug_drx_list(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->drx) {
		plugin->drx (dbg, 0, 0, 0, 0, 0, DRX_API_LIST);
	}
}

R_API bool r_debug_drx_set(RDebug *dbg, int idx, ut64 addr, int len, int rwx, int g) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->drx) {
		return plugin->drx (dbg, idx, addr, len, rwx, g, DRX_API_SET_BP);
	}
	return false;
}

R_API bool r_debug_drx_unset(RDebug *dbg, int idx) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->drx) {
		return plugin->drx (dbg, idx, 0, -1, 0, 0, DRX_API_REMOVE_BP);
	}
	return false;
}

R_API ut64 r_debug_get_baddr(RDebug *dbg, const char *file) {
	R_RETURN_VAL_IF_FAIL (dbg, 0LL);
	if (!dbg || !dbg->iob.io || !dbg->iob.io->desc) {
		return 0LL;
	}
	if (!strcmp (dbg->iob.io->desc->plugin->meta.name, "gdb")) { // this is very bad
		// Tell gdb that we want baddr, not full mem map
		dbg->iob.system (dbg->iob.io, "baddr");
	}
	int pid = r_io_desc_get_pid (dbg->iob.io->desc);
	int tid = r_io_desc_get_tid (dbg->iob.io->desc);
	if (pid < 0 || tid < 0) {
		return 0LL;
	}
	if (!r_debug_attach (dbg, pid)) {
		return 0LL;
	}
#if R2__WINDOWS__
	ut64 base;
	bool ret = r_io_desc_get_base (dbg->iob.io->desc, &base);
	if (ret) {
		return base;
	}
#endif
	RListIter *iter;
	RDebugMap *map;
	r_debug_select (dbg, pid, tid);
	r_debug_map_sync (dbg);
	char *abspath = r_sys_pid_to_path (pid);
	if (file) {
#if !R2__WINDOWS__
		if (!abspath) {
			abspath = r_file_abspath (file);
		}
#endif
		if (!abspath) {
			abspath = strdup (file);
		}
	}
	if (abspath) {
		r_list_foreach (dbg->maps, iter, map) {
			if (!strcmp (abspath, map->name)) {
				free (abspath);
				return map->addr;
			}
		}
		free (abspath);
	}
	// fallback resolution (osx/w32?)
	// we assume maps to be loaded in order, so lower addresses come first
	r_list_foreach (dbg->maps, iter, map) {
		if (map->perm == 5) { // r-x
			return map->addr;
		}
	}
	return 0LL;
}

R_API int r_debug_cmd(RDebug *dbg, const char *s) {
	R_RETURN_VAL_IF_FAIL (dbg, 0);
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->cmd) {
		return plugin->cmd (dbg, s);
	}
	return 0;
}

R_API void r_debug_bp_rebase(RDebug *dbg, ut64 old_base, ut64 new_base) {
	R_RETURN_IF_FAIL (dbg);
	RBreakpointItem *bp;
	RListIter *iter;
	ut64 diff = new_base - old_base;
	// update bp->baddr
	dbg->bp->baddr = new_base;

	// update bp's address
	r_list_foreach (dbg->bp->bps, iter, bp) {
		bp->addr += diff;
		bp->delta = bp->addr - dbg->bp->baddr;
	}
}
