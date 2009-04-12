/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>

R_API int r_debug_bp_add(struct r_debug_t *dbg, u64 addr, int size)
{
	struct r_bp_item_t *bp;
	if (dbg->read == NULL) {
		eprintf("No dbg->read callback defined\n");
		return -1;
	}
	/* read bytes affected */
	u8 *buf = (u8 *)malloc(size);
	dbg->read(dbg->pid, addr, buf, size);
	/* register breakpoint in r_bp */
	bp = r_bp_add_bp(&dbg->bp, buf, addr, size, 0, R_BP_EXEC);
	/* if already set, r_bp should return false */
	free(buf);
	return bp!=NULL;
}

R_API int r_debug_bp_del(struct r_debug_t *dbg, u64 addr)
{
	return r_bp_del_bp(&dbg->bp, addr);
}

/**
 * reflect all r_bp stuff in the process using dbg->bp_write
 */
R_API int r_debug_bp_restore(struct r_debug_t *dbg, int set)
{
	if (set) {
		/* write bbytes from every breakpoint in r_bp */
	} else {
		/* write obytes from every breakpoint */
	}
	return R_TRUE;
}

R_API int r_debug_bp_list(struct r_debug_t *dbg, int rad)
{
	return r_bp_list(&dbg->bp, rad);
}
