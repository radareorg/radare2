#include <r_bp.h>

// TODO: rename from r_debug_ ... 
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
	return bp!=NULL;
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
