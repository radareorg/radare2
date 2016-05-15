/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_bp.h>
#include "../config.h"

// TODO: rename from r_debug_ ...

/**
 * reflect all r_bp stuff in the process using dbg->bp_write or ->breakpoint
 */
R_API int r_bp_restore(RBreakpoint *bp, int set) {
	return r_bp_restore_except (bp, set, 0);
}

/**
 * reflect all r_bp stuff in the process using dbg->bp_write or ->breakpoint
 *
 * except the specified breakpoint...
 */
R_API int r_bp_restore_except(RBreakpoint *bp, int set, ut64 addr) {
	RListIter *iter;
	RBreakpointItem *b;

	r_list_foreach (bp->bps, iter, b) {
		if (addr && b->addr == addr)
			continue;
		if (bp->breakpoint && bp->breakpoint (b, set, bp->user))
			continue;
		/* write obytes from every breakpoint in r_bp if not handled by plugin */
		if (set) {
			//eprintf ("Setting bp at 0x%08"PFMT64x"\n", b->addr);
			if (b->hw || !b->bbytes)
				eprintf ("hw breakpoints not yet supported\n");
			else
				bp->iob.write_at (bp->iob.io, b->addr, b->bbytes, b->size);
		} else {
			//eprintf ("Clearing bp at 0x%08"PFMT64x"\n", b->addr);
			if (b->hw || !b->obytes)
				eprintf ("hw breakpoints not yet supported\n");
			else
				bp->iob.write_at (bp->iob.io, b->addr, b->obytes, b->size);
		}
	}
	return true;
}

R_API int r_bp_recoil(RBreakpoint *bp, ut64 addr) {
	RBreakpointItem *b = r_bp_get_in (bp, addr, 0); //XXX Don't care about rwx
	if (b) {
		//eprintf("HIT AT ADDR 0x%"PFMT64x"\n", addr);
		//eprintf("  recoil = %d\n", b->recoil);
		//eprintf("  size = %d\n", b->size);
		if (!b->hw && b->addr == addr)
			return b->recoil;
	}
	return 0;
}
