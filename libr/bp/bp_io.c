/* radare - LGPL - Copyright 2009-2018 pancake */

#include <r_bp.h>
#include <config.h>

R_API void r_bp_restore_one(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	if (set) {
		//eprintf ("Setting bp at 0x%08"PFMT64x"\n", b->addr);
		if (b->hw || !b->bbytes) {
			eprintf ("hw breakpoints not yet supported\n");
		} else {
			bp->iob.write_at (bp->iob.io, b->addr, b->bbytes, b->size);
		}
	} else {
		//eprintf ("Clearing bp at 0x%08"PFMT64x"\n", b->addr);
		if (b->hw || !b->obytes) {
			eprintf ("hw breakpoints not yet supported\n");
		} else {
			bp->iob.write_at (bp->iob.io, b->addr, b->obytes, b->size);
		}
	}
}

/**
 * reflect all r_bp stuff in the process using dbg->bp_write or ->breakpoint
 */
R_API int r_bp_restore(RBreakpoint *bp, bool set) {
	return r_bp_restore_except (bp, set, UT64_MAX);
}

/**
 * reflect all r_bp stuff in the process using dbg->bp_write or ->breakpoint
 *
 * except the specified breakpoint...
 */
R_API bool r_bp_restore_except(RBreakpoint *bp, bool set, ut64 addr) {
	bool rc = true;
	RListIter *iter;
	RBreakpointItem *b;

	if (set && bp->bpinmaps) {
		bp->corebind.syncDebugMaps (bp->corebind.core);
	}

	r_list_foreach (bp->bps, iter, b) {
		if (addr && b->addr == addr) {
			continue;
		}
		// Avoid restoring disabled breakpoints
		if (set && !b->enabled) {
			continue;
		}
		// Check if the breakpoint is in a valid map
		if (set && bp->bpinmaps && !r_bp_is_valid (bp, b)) {
			continue;
		}
		if (bp->breakpoint && bp->breakpoint (bp, b, set)) {
			continue;
		}

		/* write (o|b)bytes from every breakpoint in r_bp if not handled by plugin */
		r_bp_restore_one (bp, b, set);
		rc = true;
	}
	return rc;
}
