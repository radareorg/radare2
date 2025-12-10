/* radare - LGPL - Copyright 2010-2017 pancake<nopcode.org>, rkx1209 */

#include <r_bp.h>

static void r_bp_watch_add_hw(RBreakpoint *bp, RBreakpointItem *b) {
	if (bp->breakpoint) {
		bp->breakpoint (bp, b, true);
	}
}

R_API RBreakpointItem* r_bp_watch_add(RBreakpoint *bp, ut64 addr, int size, int hw, int perm) {
	// use R_RETURN precondition checks in all R_API functions
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (r_bp_get_in (bp, addr, perm)) {
		R_LOG_WARN ("Breakpoint already set at this address");
		return NULL;
	}
	RBreakpointItem *b = r_bp_item_new (bp);
	b->addr = addr + bp->delta;
	b->size = size;
	b->enabled = true;
	b->perm = perm;
	b->hw = hw;
	if (hw) {
		r_bp_watch_add_hw (bp, b);
	} else {
		R_LOG_TODO ("Software watchpoint is not implemented yet (use ESIL)");
		/* TODO */
	}
	r_list_append (bp->bps, b);
	return b;
}

R_API void r_bp_watch_del(void) {
	R_LOG_TODO ("r_bp_watch_del not implemented");
}
