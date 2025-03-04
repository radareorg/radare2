/* radare - LGPL - Copyright 2008-2024 - pancake, Luc Tielen */

#include <r_debug.h>
#include <r_util/r_str.h>
#include <sdb/ht_pu.h>

R_VEC_TYPE(RVecDebugTracepoint, RDebugTracepointItem);

R_API RDebugTrace *r_debug_trace_new(void) {
	RDebugTrace *t = R_NEW0 (RDebugTrace);
	if (!t) {
		return NULL;
	}
	t->tag = 1; // UT32_MAX;
	t->addresses = NULL;
	t->enabled = false;
	t->traces = RVecDebugTracepoint_new ();
	if (!t->traces) {
		r_debug_trace_free (t);
		return NULL;
	}
	t->ht = ht_pp_new0 ();
	// t->ht = ht_pu_new0 ();
	if (!t->ht) {
		r_debug_trace_free (t);
		return NULL;
	}
	return t;
}

R_API void r_debug_trace_free(RDebugTrace *t) {
	if (t) {
		RVecDebugTracepoint_free (t->traces);
		ht_pp_free (t->ht);
		// ht_pu_free (t->ht);
		free (t);
	}
}

// TODO: added overlap/mask support here... wtf?
// TODO: think about tagged traces .. must return 0 or ntag :?
R_API int r_debug_trace_tag(RDebug *dbg, int tag) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->trace, 0);
	ut32 ntag = (tag > 0)? (ut32)tag: UT32_MAX;
	dbg->trace->tag = ntag;
	return ntag;
}

R_API bool r_debug_trace_ins_before(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	RListIter *it, *it_tmp;
	RAnalValue *val;
	ut8 buf_pc[32];

	// Analyze current instruction
	const char *pcreg = r_reg_alias_getname (dbg->reg, R_REG_ALIAS_PC);
	if (!pcreg) {
		return false;
	}
	ut64 pc = r_debug_reg_get (dbg, pcreg);
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
	if (!r_anal_op (dbg->anal, dbg->cur_op, pc, buf_pc, sizeof (buf_pc), R_ARCH_OP_MASK_VAL)) {
		r_anal_op_free (dbg->cur_op);
		dbg->cur_op = NULL;
		return false;
	}

	// resolve mem write address
	r_list_foreach_safe (dbg->cur_op->access, it, it_tmp, val) {
		switch (val->type) {
		case R_ANAL_VAL_REG:
			if (!(val->access & R_PERM_W)) {
				r_list_delete (dbg->cur_op->access, it);
			}
			break;
		case R_ANAL_VAL_MEM:
			if (val->memref > 32) {
				R_LOG_ERROR ("adding changes to %d bytes in memory", val->memref);
				r_list_delete (dbg->cur_op->access, it);
				break;
			}

			if (val->access & R_PERM_W) {
				// resolve memory address
				ut64 addr = 0;
				addr += val->delta;
				if (val->seg) {
					addr += r_reg_getv (dbg->reg, val->seg);
				}
				if (val->reg) {
					addr += r_reg_getv (dbg->reg, val->reg);
				}
				if (val->regdelta) {
					int mul = val->mul ? val->mul : 1;
					addr += mul * r_reg_getv (dbg->reg, val->regdelta);
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
		if (!(val->access & R_PERM_W)) {
			continue;
		}

		switch (val->type) {
		case R_ANAL_VAL_REG:
		{
			if (!val->reg) {
				R_LOG_ERROR ("invalid register, unable to trace register state");
				continue;
			}
			RRegItem *ri = r_reg_get (dbg->reg, val->reg, R_REG_TYPE_GPR);
			if (ri) {
				// add reg write
				ut64 data = r_reg_get_value (dbg->reg, ri);
				r_debug_session_add_reg_change (dbg->session, ri->arena, ri->offset, data);
			} else {
				R_LOG_WARN ("Missing register %s", val->reg);
			}
			break;
		}
		case R_ANAL_VAL_MEM:
		{
			ut8 buf[32] = {0};
			if (!dbg->iob.read_at (dbg->iob.io, val->base, buf, val->memref)) {
				R_LOG_ERROR ("reading memory at 0x%"PFMT64x, val->base);
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
R_API bool r_debug_trace_pc(RDebug *dbg, ut64 pc) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->trace, false);
	ut8 buf[32];
	RAnalOp op = {0};
	if (!dbg->iob.is_valid_offset (dbg->iob.io, pc, 0)) {
		R_LOG_ERROR ("trace_pc: cannot read memory at 0x%"PFMT64x, pc);
		return false;
	}
	int res = dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
	if (res > 0 && r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf), R_ARCH_OP_MASK_ESIL) < 1) {
		R_LOG_ERROR ("trace_pc: cannot get opcode size at 0x%"PFMT64x, pc);
		return false;
	}
	r_debug_trace_op (dbg, &op);
	r_anal_op_fini (&op);
	return true;
}

R_API void r_debug_trace_op(RDebug *dbg, RAnalOp *op) {
	R_RETURN_IF_FAIL (dbg && dbg->trace);
	if (dbg->trace->enabled) {
		r_debug_trace_add (dbg, op->addr, op->size);
	}
}

R_API void r_debug_trace_at(RDebug *dbg, const char *str) {
	R_RETURN_IF_FAIL (dbg && dbg->trace);
	// TODO: parse offsets and so use ut64 instead of strstr()
	free (dbg->trace->addresses);
	dbg->trace->addresses = R_STR_ISNOTEMPTY (str)? strdup (str): NULL;
}

R_API RDebugTracepointItem *r_debug_trace_get(RDebug *dbg, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->trace, NULL);
	const int tag = dbg->trace->tag;
	r_strf_var (key, 64, "%d.%"PFMT64x, tag, addr);
	bool found = false;
	int pos = (int)(size_t)ht_pp_find (dbg->trace->ht, key, &found);
	if (found) {
		return RVecDebugTracepoint_at (dbg->trace->traces, pos - 1);
	}
	return NULL;
	// return ht_pp_find (dbg->trace->ht, key, NULL);
}

static int cmpaddr(const RListInfo *a, const RListInfo *b) {
	const ut64 begin_a = r_itv_begin (a->pitv);
	const ut64 begin_b = r_itv_begin (b->pitv);
	return (begin_a > begin_b)? 1: (begin_a < begin_b)? -1: 0;
}

static void r_debug_trace_list_json(RDebug *dbg) {
	int tag = dbg->trace->tag;
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_kn (pj, "tag", tag);
	pj_ka (pj, "traces");

	RDebugTracepointItem *trace;
	R_VEC_FOREACH (dbg->trace->traces, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			pj_o (pj);
			pj_kn (pj, "addr", trace->addr);
			pj_kn (pj, "tag", trace->tag);
			pj_kn (pj, "times", trace->times);
			pj_kn (pj, "count", trace->count);
			pj_kn (pj, "size", trace->size);
			pj_end (pj);
		}
	}

	pj_end (pj);
	pj_end (pj);
	char *s = pj_drain (pj);
	dbg->cb_printf ("%s\n", s);
	free (s);
}

static void r_debug_trace_list_quiet(RDebug *dbg) {
	int tag = dbg->trace->tag;
	RDebugTracepointItem *trace;
	R_VEC_FOREACH (dbg->trace->traces, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			dbg->cb_printf ("0x%"PFMT64x"\n", trace->addr);
		}
	}
}

static inline void listinfo_fini(RListInfo *info) {
	R_RETURN_IF_FAIL (info);
	free (info->name);
	free (info->extra);
}

R_VEC_TYPE_WITH_FINI (RVecListInfo, RListInfo, listinfo_fini);

static void r_debug_trace_list_table(RDebug *dbg, ut64 offset, RTable *t) {
	RVecListInfo info_vec;
	RVecListInfo_init (&info_vec);

	bool flag = false;
	int tag = dbg->trace->tag;

	RDebugTracepointItem *trace;
	R_VEC_FOREACH (dbg->trace->traces, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			RListInfo *info = RVecListInfo_emplace_back (&info_vec);
			if (!info) {
				RVecListInfo_fini (&info_vec);
				return;
			}
			info->pitv = (RInterval) {trace->addr, trace->size};
			info->vitv = info->pitv;
			info->perm = -1;
			info->name = r_str_newf ("%d", trace->times);
			info->extra = r_str_newf ("%d", trace->count);
			flag = true;
		}
	}

	if (flag) {
		RVecListInfo_sort (&info_vec, cmpaddr);
		RTable *table = t? t: r_table_new ("traces");
		table->cons = r_cons_singleton ();
		RIO *io = dbg->iob.io;
		r_table_visual_vec (table, &info_vec, offset, 1, r_cons_get_size (NULL), io->va);
		char *s = r_table_tostring (table);
		io->cb_printf ("%s", s);
		free (s);
		r_table_free (table);
	}

	RVecListInfo_fini (&info_vec);
}

static void r_debug_trace_list_make(RDebug *dbg) {
	int tag = dbg->trace->tag;
	RDebugTracepointItem *trace;
	R_VEC_FOREACH (dbg->trace->traces, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			dbg->cb_printf ("dt+ 0x%"PFMT64x" %d\n", trace->addr, trace->times);
		}
	}
}

static void r_debug_trace_list_default(RDebug *dbg) {
	int tag = dbg->trace->tag;
	RDebugTracepointItem *trace;
	R_VEC_FOREACH (dbg->trace->traces, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			dbg->cb_printf ("0x%08"PFMT64x" size=%d count=%d times=%d tag=%d\n",
				trace->addr, trace->size, trace->count, trace->times, trace->tag);
		}
	}
}

R_API void r_debug_trace_list(RDebug *dbg, int mode, ut64 offset, RTable *t) {
	R_RETURN_IF_FAIL (dbg && dbg->trace);
	switch (mode) {
	case 'j':
		r_debug_trace_list_json (dbg);
		break;
	case 'q':
		r_debug_trace_list_quiet (dbg);
		break;
	case '=':
		r_debug_trace_list_table (dbg, offset, t);
		break;
	case 1:
	case '*':
		r_debug_trace_list_make (dbg);
		break;
	default:
		r_debug_trace_list_default (dbg);
		break;
	}
}

// XXX: find better name, make it public?
static bool r_debug_trace_is_traceable(RDebug *dbg, ut64 addr) {
	if (dbg->trace->addresses) {
		r_strf_var (addr_str, 64, "0x%08"PFMT64x, addr);
		if (!strstr (dbg->trace->addresses, addr_str)) {
			return false;
		}
	}
	return true;
}

R_API RDebugTracepointItem *r_debug_trace_add(RDebug *dbg, ut64 addr, int size) {
	R_RETURN_VAL_IF_FAIL (dbg, NULL);
	const int tag = dbg->trace->tag;
	if (!r_debug_trace_is_traceable (dbg, addr)) {
		return NULL;
	}
	r_anal_trace_bb (dbg->anal, addr);
	int last_times = 1;
	RDebugTracepointItem *last = r_debug_trace_get (dbg, addr);
	if (last) {
		RDebugTracepointItem *endtp = RVecDebugTracepoint_last (dbg->trace->traces);
		if (last == endtp) {
			// avoid tracing the same instruction twice
			return NULL;
		}
		last_times = last->times + 1;
	}
	int pos = RVecDebugTracepoint_length (dbg->trace->traces) + 1;
	// emplacedback pointers are not constant, so we may rely on the index instead of ptr
	RDebugTracepointItem *tp = RVecDebugTracepoint_emplace_back (dbg->trace->traces);
	if (R_LIKELY (tp)) {
		tp->stamp = r_time_now ();
		tp->addr = addr;
		tp->tags = tag;
		tp->size = size;
		tp->count = ++dbg->trace->count;
		tp->times = last_times;
		r_strf_var (key, 64, "%d.%"PFMT64x, tag, addr);
		void *ip = (void*)(size_t)(pos);
		ht_pp_update (dbg->trace->ht, key, ip);
		// for some reason pu mode doesnt work but storing integers as pointers works
		// ht_pu_update (dbg->trace->ht, key, pos);
		// ht_pp_delete (dbg->trace->ht, key);
		// ht_pu_insert (dbg->trace->ht, key, pos);
		// eprintf ("UP %s %llx\n", key, addr);
	}
	return tp;
}

R_API void r_debug_trace_reset(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	RDebugTrace *t = dbg->trace;
	ht_pp_free (t->ht);
	t->ht = ht_pp_new0 ();
	// ht_pu_free (t->ht);
	// t->ht = ht_pu_new0 ();
	RVecDebugTracepoint_free (t->traces);
	t->traces = RVecDebugTracepoint_new ();
}
