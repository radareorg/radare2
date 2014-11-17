/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_bp.h>
#include "../config.h"

// TODO: rename from r_debug_ ... 
#if 0
R_API int r_debug_bp_enable(struct r_debug_t *dbg, ut64 addr, int set)
{
	struct r_bp_item_t *bp = r_bp_enable(dbg->bp, addr, set);
	struct r_io_bind_t *iob;
	if (bp) {
		iob = &dbg->bp->iob;
		iob->set_fd(iob->io, dbg->pid); // HUH?
		if (set) iob->write_at(iob->io, addr, bp->bbytes, bp->size);
		else iob->write_at(iob->io, addr, bp->obytes, bp->size);
	}
	return (bp!=NULL)?R_TRUE:R_FALSE;
}

// XXX this must be implemented in r_bp.. not here!!1
R_API int r_debug_bp_add(struct r_debug_t *dbg, ut64 addr, int size, int hw, int rwx)
{
	ut8 *buf;
	int ret = R_FALSE;
	struct r_bp_item_t *bp;
	struct r_io_bind_t *iob;
	if (dbg->bp->iob.init == R_FALSE) {
		eprintf("No dbg->read callback defined\n");
		return -1; // return -1?
	}
	iob = &dbg->bp->iob;
	/* read bytes affected */
	buf = (ut8 *)malloc(size);
	if (buf == NULL)
		return -1;
	iob->set_fd(iob->io, dbg->pid);
	iob->read_at(iob->io, addr, buf, size);
	/* register breakpoint in r_bp */
	// XXX. bpadd here?!?
	if (hw) bp = r_bp_add_sw(&dbg->bp, buf, addr, size, 0, R_BP_EXEC);
	else bp = r_bp_add_sw(&dbg->bp, buf, addr, size, 0, R_BP_EXEC);
	if (bp) {
		if (dbg->h && (!dbg->h->bp_write || !dbg->h->bp_write(dbg->pid, addr, size, hw, rwx )))
			iob->write_at(iob->io, addr, bp->bbytes, size);
		/* if already set, r_bp should return false */
		ret = R_TRUE;
	}
	free(buf);
	return ret;
}
#endif

/**
 * reflect all r_bp stuff in the process using dbg->bp_write or ->breakpoint
 */
R_API int r_bp_restore(struct r_bp_t *bp, int set) {
	RListIter *iter;
	RBreakpointItem *b;

	r_list_foreach (bp->bps, iter, b) {
		if (bp->breakpoint && bp->breakpoint (b, set, bp->user))
			continue;
		/* write obytes from every breakpoint in r_bp if not handled by plugin */
		if (set) {
			//eprintf ("Setting bp at 0x%08"PFMT64x"\n", b->addr);
			if (b->hw || !b->obytes)
				eprintf ("hw breakpoints not yet supported\n");
			else bp->iob.write_at (bp->iob.io, b->addr, b->bbytes, b->size);
		} else {
			//eprintf ("Clearing bp at 0x%08"PFMT64x"\n", b->addr);
			if (b->hw || !b->obytes)
				eprintf ("hw breakpoints not yet supported\n");
			else bp->iob.write_at (bp->iob.io, b->addr, b->obytes, b->size);
		}
	}
	
	return R_TRUE;
}

R_API int r_bp_recoil(RBreakpoint *bp, ut64 addr) {
	RBreakpointItem *b = r_bp_get_in (bp, addr, 0); //XXX Don't care about rwx
	if (b) {
		//eprintf("HIT AT ADDR 0x%"PFMT64x"\n", addr);
		//eprintf("  recoil = %d\n", b->recoil);
		//eprintf("  size = %d\n", b->size);
		if (!b->hw && ((b->addr + b->size) == addr))
			return b->recoil;
	}
	return 0;
}
