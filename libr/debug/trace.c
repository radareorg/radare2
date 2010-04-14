/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <r_debug.h>

/* first argument can leak in bad usage.. weird */
R_API void r_debug_trace_reset (RDebug *dbg, int liberate) {
	if (liberate)
		r_list_destroy (dbg->traces);
	dbg->traces = r_list_new ();
	dbg->traces->free = free;
	dbg->trace_tag = -1;
}

R_API void r_debug_trace_tag (RDebug *dbg, int tag) {
	dbg->trace_tag = tag;
}

R_API int r_debug_trace_pc (RDebug *dbg) {
	RRegisterItem *ri;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
	ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], -1);
	if (ri) {
		ut64 addr = r_reg_get_value (dbg->reg, ri);
		int size = 1; // TODO: read code if not cached and analyze opcode
		r_debug_trace_add (dbg, addr, size, dbg->trace_tag);
		return R_TRUE;
	} else eprintf ("trace_pc: cannot get prgoram counter\n");
	return R_FALSE;
}

R_API RDebugTrace *r_debug_trace_get (RDebug *dbg, ut64 addr, int tag) {
	/* TODO: handle opcode size .. warn when jumping in the middle of instructions */
	RListIter *iter = r_list_iterator (dbg->traces);
	while (r_list_iter_next (iter)) {
		RDebugTrace *trace = r_list_iter_get (iter);
		if (tag != 0 && !(dbg->trace_tag & (1<<tag)))
			continue;
		if (trace->addr == addr)
			return trace;
	}
	return NULL;
}

R_API void r_debug_trace_list (RDebug *dbg, int tag) {
	RListIter *iter = r_list_iterator (dbg->traces);
	while (r_list_iter_next (iter)) {
		RDebugTrace *trace = r_list_iter_get (iter);
		if (!trace->tags || (tag & trace->tags))
			eprintf ("0x%08"PFMT64x" %d\n", trace->addr, trace->count);
	}
}

/* sort insert, or separated sort function ? */
/* TODO: detect if inner opcode */
R_API int r_debug_trace_add (RDebug *dbg, ut64 addr, int size, int tag) {
	RDebugTrace *trace = r_debug_trace_get (dbg, addr, tag);
	if (!trace) {
		trace = R_NEW (RDebugTrace);
		trace->stamp = r_sys_now ();
		trace->addr = addr;
		trace->tags = tag;
		trace->size = size;
		trace->count = 0;
		r_list_append (dbg->traces, trace);
	} else trace->count++;
	return trace->count;
}
