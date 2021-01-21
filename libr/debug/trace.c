/* radare - LGPL - Copyright 2008-2020 - pancake */

#include <r_debug.h>

// DO IT WITH SDB

R_API RDebugTrace *r_debug_trace_new (void) {
	RDebugTrace *t = R_NEW0 (RDebugTrace);
	if (!t) {
		return NULL;
	}
	t->tag = 1; // UT32_MAX;
	t->addresses = NULL;
	t->enabled = false;
	t->traces = r_list_new ();
	if (!t->traces) {
		r_debug_trace_free (t);
		return NULL;
	}
	t->traces->free = free;
	t->ht = ht_pp_new0 ();
	if (!t->ht) {
		r_debug_trace_free (t);
		return NULL;
	}
	return t;
}

R_API void r_debug_trace_free (RDebugTrace *trace) {
	if (!trace) {
		return;
	}
	r_list_purge (trace->traces);
	free (trace->traces);
	ht_pp_free (trace->ht);
	R_FREE (trace);
}

// TODO: added overlap/mask support here... wtf?
// TODO: think about tagged traces
R_API int r_debug_trace_tag (RDebug *dbg, int tag) {
	//if (tag>0 && tag<31) core->dbg->trace->tag = 1<<(sz-1);
	return (dbg->trace->tag = (tag>0)? tag: UT32_MAX);
}

R_API bool r_debug_trace_ins_before(RDebug *dbg) {
	RListIter *it, *it_tmp;
	RAnalValue *val;
	ut8 buf_pc[32];

	// Analyze current instruction
	ut64 pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	if (!dbg->iob.read_at) {
		return false;
	}
	if (!dbg->iob.read_at (dbg->iob.io, pc, buf_pc, sizeof (buf_pc))) {
		return false;
	}
	dbg->cur_op = R_NEW0 (RAnalOp);
	if (!dbg->cur_op) {
		return false;
	}
	if (!r_anal_op (dbg->anal, dbg->cur_op, pc, buf_pc, sizeof (buf_pc), R_ANAL_OP_MASK_VAL)) {
		r_anal_op_free (dbg->cur_op);
		dbg->cur_op = NULL;
		return false;
	}

	// resolve mem write address
	r_list_foreach_safe (dbg->cur_op->access, it, it_tmp, val) {
		switch (val->type) {
		case R_ANAL_VAL_REG:
			if (!(val->access & R_ANAL_ACC_W)) {
				r_list_delete (dbg->cur_op->access, it);
			}
			break;
		case R_ANAL_VAL_MEM:
			if (val->memref > 32) {
				eprintf ("Error: adding changes to %d bytes in memory.\n", val->memref);
				r_list_delete (dbg->cur_op->access, it);
				break;
			}

			if (val->access & R_ANAL_ACC_W) {
				// resolve memory address
				ut64 addr = 0;
				addr += val->delta;
				if (val->seg) {
					addr += r_reg_get_value (dbg->reg, val->seg);
				}
				if (val->reg) {
					addr += r_reg_get_value (dbg->reg, val->reg);
				}
				if (val->regdelta) {
					int mul = val->mul ? val->mul : 1;
					addr += mul * r_reg_get_value (dbg->reg, val->regdelta);
				}
				// resolve address into base for ins_after
				val->base = addr;
			} else {
				r_list_delete (dbg->cur_op->access, it);
			}
		default:
			break;
		}
	}
	return true;
}

R_API bool r_debug_trace_ins_after(RDebug *dbg) {
	RListIter *it;
	RAnalValue *val;

	// Add reg/mem write change
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, false);
	r_list_foreach (dbg->cur_op->access, it, val) {
		if (!(val->access & R_ANAL_ACC_W)) {
			continue;
		}

		switch (val->type) {
		case R_ANAL_VAL_REG:
		{
			if (!val->reg) {
				R_LOG_ERROR("invalid register, unable to trace register state\n");
				continue;
			}
			ut64 data = r_reg_get_value (dbg->reg, val->reg);

			// add reg write
			r_debug_session_add_reg_change (dbg->session, val->reg->arena, val->reg->offset, data);
			break;
		}
		case R_ANAL_VAL_MEM:
		{
			ut8 buf[32] = { 0 };
			if (!dbg->iob.read_at (dbg->iob.io, val->base, buf, val->memref)) {
				eprintf ("Error reading memory at 0x%"PFMT64x"\n", val->base);
				break;
			}

			// add mem write
			size_t i;
			for (i = 0; i < val->memref; i++) {
				r_debug_session_add_mem_change (dbg->session, val->base + i, buf[i]);
			}
			break;
		}
		default:
			break;
		}
	}
	r_anal_op_free (dbg->cur_op);
	dbg->cur_op = NULL;
	return true;
}

/*
 * something happened at the given pc that we need to trace
 */
R_API int r_debug_trace_pc(RDebug *dbg, ut64 pc) {
	ut8 buf[32];
	RAnalOp op = {0};
	if (!dbg->iob.is_valid_offset (dbg->iob.io, pc, 0)) {
		eprintf ("trace_pc: cannot read memory at 0x%"PFMT64x"\n", pc);
		return false;
	}
	(void)dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
	if (r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf), R_ANAL_OP_MASK_ESIL) < 1) {
		eprintf ("trace_pc: cannot get opcode size at 0x%"PFMT64x"\n", pc);
		return false;
	}
	r_debug_trace_op (dbg, &op);
	r_anal_op_fini (&op);
	return true;
}

R_API void r_debug_trace_op(RDebug *dbg, RAnalOp *op) {
	static ut64 oldpc = UT64_MAX; // Must trace the previously traced instruction
	if (dbg->trace->enabled) {
		if (dbg->anal->esil) {
			r_anal_esil_trace_op (dbg->anal->esil, op);
		} else {
			if (dbg->verbose) {
				eprintf ("Run aeim to get dbg->anal->esil initialized\n");
			}
		}
	}
	if (oldpc != UT64_MAX) {
		r_debug_trace_add (dbg, oldpc, op->size); //XXX review what this line really do
	}
	oldpc = op->addr;
}

R_API void r_debug_trace_at(RDebug *dbg, const char *str) {
	// TODO: parse offsets and so use ut64 instead of strstr()
	free (dbg->trace->addresses);
	dbg->trace->addresses = (str&&*str)? strdup (str): NULL;
}

R_API RDebugTracepoint *r_debug_trace_get(RDebug *dbg, ut64 addr) {
	int tag = dbg->trace->tag;
	return ht_pp_find (dbg->trace->ht,
		sdb_fmt ("trace.%d.%"PFMT64x, tag, addr), NULL);
}

static int cmpaddr(const void *_a, const void *_b) {
	const RListInfo *a = _a, *b = _b;
	return (r_itv_begin (a->pitv) > r_itv_begin (b->pitv))? 1:
		 (r_itv_begin (a->pitv) < r_itv_begin (b->pitv))? -1: 0;
}

R_API void r_debug_trace_list(RDebug *dbg, int mode, ut64 offset) {
	int tag = dbg->trace->tag;
	RListIter *iter;
	bool flag = false;
	RList *info_list = r_list_new ();
	if (!info_list && mode == '=') {
		return;
	}
	RDebugTracepoint *trace;
	r_list_foreach (dbg->trace->traces, iter, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			switch (mode) {
			case 'q':
				dbg->cb_printf ("0x%"PFMT64x"\n", trace->addr);
				break;
			case '=': {
				RListInfo *info = R_NEW0 (RListInfo);
				if (!info) {
					return;
				}
				info->pitv = (RInterval) {trace->addr, trace->size};
				info->vitv = info->pitv;
				info->perm = -1;
				info->name = r_str_newf ("%d", trace->times);
				info->extra = r_str_newf ("%d", trace->count);
				r_list_append (info_list, info);
				flag = true;
			}	break;
			case 1:
			case '*':
				dbg->cb_printf ("dt+ 0x%"PFMT64x" %d\n", trace->addr, trace->times);
				break;
			default:
				dbg->cb_printf ("0x%08"PFMT64x" size=%d count=%d times=%d tag=%d\n",
					trace->addr, trace->size, trace->count, trace->times, trace->tag);
				break;
			}
		}
	}
	if (flag) {
		r_list_sort (info_list, cmpaddr);
		RTable *table = r_table_new ("traces");
		table->cons = r_cons_singleton();
		RIO *io = dbg->iob.io;
		r_table_visual_list (table, info_list, offset, 1,
			r_cons_get_size (NULL), io->va);
		io->cb_printf ("\n%s\n", r_table_tostring (table));
		r_table_free (table);
		r_list_free (info_list);
	}
}

// XXX: find better name, make it public?
static int r_debug_trace_is_traceable(RDebug *dbg, ut64 addr) {
	if (dbg->trace->addresses) {
		char addr_str[32];
		snprintf (addr_str, sizeof (addr_str), "0x%08"PFMT64x, addr);
		if (!strstr (dbg->trace->addresses, addr_str)) {
			return false;
		}
	}
	return true;
}

R_API RDebugTracepoint *r_debug_trace_add (RDebug *dbg, ut64 addr, int size) {
	RDebugTracepoint *tp;
	int tag = dbg->trace->tag;
	if (!r_debug_trace_is_traceable (dbg, addr)) {
		return NULL;
	}
	r_anal_trace_bb (dbg->anal, addr);
	tp = R_NEW0 (RDebugTracepoint);
	if (!tp) {
		return NULL;
	}
	tp->stamp = r_time_now ();
	tp->addr = addr;
	tp->tags = tag;
	tp->size = size;
	tp->count = ++dbg->trace->count;
	tp->times = 1;
	r_list_append (dbg->trace->traces, tp);
	ht_pp_update (dbg->trace->ht,
		sdb_fmt ("trace.%d.%"PFMT64x, tag, addr), tp);
	return tp;
}

R_API void r_debug_trace_reset (RDebug *dbg) {
	RDebugTrace *t = dbg->trace;
	r_list_purge (t->traces);
	ht_pp_free (t->ht);
	t->ht = ht_pp_new0 ();
	t->traces = r_list_new ();
	t->traces->free = free;
}
