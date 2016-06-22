/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_debug.h>

#define R_DEBUG_SDB_TRACES 1

// DO IT WITH SDB

R_API RDebugTrace *r_debug_trace_new () {
	RDebugTrace *t = R_NEW0 (RDebugTrace);
	if (!t) return NULL;
	t->tag = 1; // UT32_MAX;
	t->addresses = NULL;
	t->enabled = false;
	t->traces = r_list_new ();
	if (!t->traces) {
		r_debug_trace_free (t);
		return NULL;
	}
	t->traces->free = free;
	t->db = sdb_new0 ();
	if (!t->db) {
		r_debug_trace_free (t);
		return NULL;
	}
	return t;
}

R_API void r_debug_trace_free (RDebugTrace *trace) {
	if (!trace) return;
	r_list_purge (trace->traces);
	free (trace->traces);
	sdb_free (trace->db);
	free (trace);
	trace = NULL;
}

// TODO: added overlap/mask support here... wtf?
// TODO: think about tagged traces
R_API int r_debug_trace_tag (RDebug *dbg, int tag) {
	//if (tag>0 && tag<31) core->dbg->trace->tag = 1<<(sz-1);
	return (dbg->trace->tag = (tag>0)? tag: UT32_MAX);
}

/*
 * something happened at the given pc that we need to trace
 */
R_API int r_debug_trace_pc (RDebug *dbg, ut64 pc) {
	ut8 buf[32];
	RAnalOp op;
	static ut64 oldpc = 0LL; // Must trace the previously traced instruction

	if (dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf)) > 0) {
		if (r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf)) > 0) {
			if (oldpc != 0LL) {
				if (dbg->anal->esil) {
					if (dbg->anal->trace) {
						r_anal_esil_trace (dbg->anal->esil, &op);
					}
				}
				r_debug_trace_add (dbg, oldpc, op.size);
			}
			oldpc = pc;
			return true;
		}
		else
			eprintf ("trace_pc: cannot get opcode size at 0x%"PFMT64x"\n", pc);
	}
	//else
	//	eprintf ("trace_pc: cannot read memory at 0x%"PFMT64x"\n", pc);
	return false;
}

R_API void r_debug_trace_at(RDebug *dbg, const char *str) {
	// TODO: parse offsets and so use ut64 instead of strstr()
	free (dbg->trace->addresses);
	dbg->trace->addresses = (str&&*str)? strdup (str): NULL;
}

R_API RDebugTracepoint *r_debug_trace_get (RDebug *dbg, ut64 addr) {
	Sdb *db = dbg->trace->db;
	int tag = dbg->trace->tag;
	RDebugTracepoint *trace;
#if R_DEBUG_SDB_TRACES
	trace = (RDebugTracepoint*)(void*)(size_t)sdb_num_get (db,
		sdb_fmt (0, "trace.%d.%"PFMT64x, tag, addr), NULL);
	return trace;
#else
	RListIter *iter;
	r_list_foreach (dbg->trace->traces, iter, trace) {
		if (tag != 0 && !(dbg->trace->tag & (1<<tag)))
			continue;
		if (trace->addr == addr)
			return trace;
	}
#endif
	return NULL;
}

R_API void r_debug_trace_list (RDebug *dbg, int mode) {
	int tag = dbg->trace->tag;
	RListIter *iter;
	RDebugTracepoint *trace;
	r_list_foreach (dbg->trace->traces, iter, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			switch (mode) {
			case 1:
			case '*':
				dbg->cb_printf ("at+ 0x%"PFMT64x" %d\n", trace->addr, trace->times);
				break;
			case 'd':
				dbg->cb_printf ("pd 1 @ 0x%"PFMT64x"\n", trace->addr);
				break;
			case 'l':
				dbg->cb_printf ("0x%"PFMT64x" ", trace->addr);
				break;
			default:
				dbg->cb_printf ("0x%08"PFMT64x" size=%d count=%d times=%d tag=%d\n",
					trace->addr, trace->size, trace->count, trace->times, trace->tag);
				break;
			}
		}
	}
}

// XXX: find better name, make it public?
static int r_debug_trace_is_traceable(RDebug *dbg, ut64 addr) {
	if (dbg->trace->addresses) {
		char addr_str[32];
		snprintf (addr_str, sizeof (addr_str), "0x%08"PFMT64x, addr);
		if (!strstr (dbg->trace->addresses, addr_str))
			return false;
	}
	return true;
}

R_API RDebugTracepoint *r_debug_trace_add (RDebug *dbg, ut64 addr, int size) {
	RDebugTracepoint *tp;
	int tag = dbg->trace->tag;
	if (!r_debug_trace_is_traceable (dbg, addr))
		return NULL;
	r_anal_trace_bb (dbg->anal, addr);
	tp = r_debug_trace_get (dbg, addr);
	if (!tp) {
		tp = R_NEW0 (RDebugTracepoint);
		if (!tp) return NULL;
		tp->stamp = r_sys_now ();
		tp->addr = addr;
		tp->tags = tag;
		tp->size = size;
		tp->count = ++dbg->trace->count;
		tp->times = 1;
		r_list_append (dbg->trace->traces, tp);
#if R_DEBUG_SDB_TRACES
		sdb_num_set (dbg->trace->db, sdb_fmt (0, "trace.%d.%"PFMT64x, tag, addr),
			(ut64)(size_t)tp, 0);
#endif
	} else tp->times++;
	return tp;
}

R_API void r_debug_trace_reset (RDebug *dbg) {
	RDebugTrace *t = dbg->trace;
	r_list_purge (t->traces);
#if R_DEBUG_SDB_TRACES
	sdb_free (t->db);
	t->db = sdb_new0 ();
#endif
	t->traces = r_list_new ();
	t->traces->free = free;
}
