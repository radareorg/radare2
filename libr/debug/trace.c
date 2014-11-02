/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_debug.h>

#define R_DEBUG_SDB_TRACES 1

// DO IT WITH SDB

R_API RDebugTrace *r_debug_trace_new () {
	RDebugTrace *t = R_NEW (RDebugTrace);
	t->tag = 1; // UT32_MAX;
	t->addresses = NULL;
	t->enabled = R_FALSE;
	t->traces = r_list_new ();
	t->traces->free = free;
	t->db = sdb_new0 ();
	return t;
}

R_API void r_debug_trace_free (RDebug *dbg) {
	if (dbg->trace == NULL)
		return;
	r_list_purge (dbg->trace->traces);
	free (dbg->trace->traces);
	sdb_free (dbg->trace->db);
	free (dbg->trace);
	dbg->trace = NULL;
}

// TODO: added overlap/mask support here... wtf?
// TODO: think about tagged traces
R_API int r_debug_trace_tag (RDebug *dbg, int tag) {
	//if (tag>0 && tag<31) core->dbg->trace->tag = 1<<(sz-1);
	return (dbg->trace->tag = (tag>0)? tag: UT32_MAX);
}

R_API int r_debug_trace_pc (RDebug *dbg) {
	ut8 buf[32];
	RRegItem *ri;
	RAnalOp op;
	static ut64 oldpc = 0LL; // Must trace the previously traced instruction
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
	if ((ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], -1))) {
		ut64 addr = r_reg_get_value (dbg->reg, ri);
		if (!addr) {
			return R_FALSE;
		}
		if (dbg->iob.read_at (dbg->iob.io, addr, buf, sizeof (buf))>0) {
			if (r_anal_op (dbg->anal, &op, addr, buf, sizeof (buf))>0) {
				if (oldpc!=0LL)
					r_debug_trace_add (dbg, oldpc, op.size);
				oldpc = addr;
				return R_TRUE;
			} else eprintf ("trace_pc: cannot get opcode size at 0x%"PFMT64x"\n", addr);
		} //else eprintf ("trace_pc: cannot read memory at 0x%"PFMT64x"\n", addr);
	} else eprintf ("trace_pc: cannot get program counter\n");
	return R_FALSE;
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
			if (mode == 1)
				dbg->printf ("at+ 0x%"PFMT64x" %d\n", trace->addr, trace->times);
			else dbg->printf ("0x%08"PFMT64x" size=%d count=%d times=%d tag=%d\n",
				trace->addr, trace->size, trace->count, trace->times, trace->tag);
		}
	}
}

// XXX: find better name, make it public?
static int r_debug_trace_is_traceable(RDebug *dbg, ut64 addr) {
	int ret = R_TRUE;
	char addr_str[32];
	if (dbg->trace->addresses) {
		snprintf (addr_str, sizeof (addr_str), "0x%08"PFMT64x, addr);
		if (!strstr (dbg->trace->addresses, addr_str))
			ret = R_FALSE;
	}
	return ret;
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
