/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_bp.h>

R_API int r_debug_bp_enable(struct r_debug_t *dbg, u64 addr, int set)
{
	struct r_bp_item_t *bp = r_bp_enable(&dbg->bp, addr, set);
	if (bp) {
		if (set) dbg->write(dbg->user, dbg->pid, addr, bp->bbytes, bp->size);
		else dbg->write(dbg->user, dbg->pid, addr, bp->obytes, bp->size);
	}
	return bp!=NULL;
}

R_API int r_debug_bp_add(struct r_debug_t *dbg, u64 addr, int size, int hw, int rwx)
{
	int ret = R_FALSE;
	struct r_bp_item_t *bp;
	if (dbg->read == NULL) {
		eprintf("No dbg->read callback defined\n");
		return -1;
	}
	/* read bytes affected */
	u8 *buf = (u8 *)malloc(size);
	dbg->read(dbg->user, dbg->pid, addr, buf, size);
	/* register breakpoint in r_bp */
	bp = r_bp_add(&dbg->bp, buf, addr, size, 0, R_BP_EXEC);
	if (bp) {
		if (dbg->h && (!dbg->h->bp_write || !dbg->h->bp_write(dbg->pid, addr, size, hw, rwx )))
			dbg->write(dbg->user, dbg->pid, addr, bp->bbytes, size);
		/* if already set, r_bp should return false */
		free(buf);
		ret = R_TRUE;
	}
	return ret;
}

R_API int r_debug_bp_del(struct r_debug_t *dbg, u64 addr)
{
	return r_bp_del(&dbg->bp, addr);
}

/**
 * reflect all r_bp stuff in the process using dbg->bp_write
 */
R_API int r_debug_bp_restore(struct r_debug_t *dbg, int set)
{
	if (set) {
		/* write bbytes from every breakpoint in r_bp */
	//	r_debug_bp_enable(dbg, addr, 1)
	} else {
		/* write obytes from every breakpoint */
	//	r_debug_bp_enable(dbg, addr, 0)
	}
	return R_TRUE;
}

R_API int r_debug_bp_list(struct r_debug_t *dbg, int rad)
{
	return r_bp_list(&dbg->bp, rad);
}
