/* radare - LGPL - Copyright 2010-2017 pancake<nopcode.org>, rkx1209 */

#include <r_bp.h>

static void r_bp_watch_add_hw(RBreakpoint *bp, RBreakpointItem *b) {
	if (bp->breakpoint) {
		bp->breakpoint (b, true, bp->user);
	}
}

R_API RBreakpointItem* r_bp_watch_add(RBreakpoint *bp, ut64 addr, int size, int hw, int rw) {
	RBreakpointItem *b;
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (r_bp_get_in (bp, addr, rw)) {
		eprintf ("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = r_bp_item_new (bp);
	b->addr = addr + bp->delta;
	b->size = size;
	b->enabled = true;
	b->rwx = rw;
	b->hw = hw;
	if (hw) {
		r_bp_watch_add_hw (bp, b);
	} else {
		/* TODO */
	}
	bp->nbps++;
	r_list_append (bp->bps, b);
	return b;
}

R_API void r_bp_watch_del() {
}

/* TODO: move into _watch */
R_API int r_bp_add_cond(struct r_bp_t *bp, const char *cond) {
	// TODO: implement contitional breakpoints
	bp->stepcont = true;
	return 0;
}

R_API int r_bp_del_cond(struct r_bp_t *bp, int idx) {
	// add contitional
	bp->stepcont = false;
	return true;
}
