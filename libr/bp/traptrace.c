/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

// TODO: use r_range here??
#include <r_bp.h>
#include <r_list.h>

R_API void r_bp_traptrace_free(void *ptr) {
	RBreakpointTrace *trace = ptr;
	free (trace->buffer);
	free (trace->traps);
	free (trace->bits);
	free (trace);
}

R_API RList *r_bp_traptrace_new() {
	RList *list = r_list_new();
	list->free = &r_bp_traptrace_free;
	return list;
}

R_API void r_bp_traptrace_enable(RBreakpoint *bp, int enable) {
	RListIter *iter = r_list_iterator (bp->traces);
	ut8 *buf;
	while (r_list_iter_next (iter)) {
		RBreakpointTrace *trace = r_list_iter_get (iter);
		if (enable) buf = trace->traps;
		else buf = trace->buffer;
		bp->iob.write_at (bp->iob.io, trace->addr, buf, trace->length);
	}
}

R_API void r_bp_traptrace_reset(RBreakpoint *bp, int hard) {
	RListIter *iter = r_list_iterator (bp->traces);
	while (r_list_iter_next (iter)) {
		RBreakpointTrace *trace = r_list_iter_get (iter);
		if (hard) {
			r_bp_traptrace_free (trace);
			r_list_delete (bp->traces, r_list_iter_cur (iter));
		} else memset (trace->bits, 0x00, trace->bitlen);
	}
}

// FIX: efficiency
R_API ut64 r_bp_traptrace_next(RBreakpoint *bp, ut64 addr) {
	int i, delta;
	RListIter *iter = r_list_iterator (bp->traces);
	while (r_list_iter_next (iter)) {
		RBreakpointTrace *trace = r_list_iter_get (iter);
		if (addr>=trace->addr && addr<=trace->addr_end) {
			delta = (int)(addr-trace->addr);
			for (i=delta; i<trace->length; i++) {
				if (BIT_CHK (trace->bits, i))
					return addr+i;
			}
		}
	}
	return 0LL;
}

R_API int r_bp_traptrace_add(RBreakpoint *bp, ut64 from, ut64 to) {
	RBreakpointTrace *trace;
	ut8 *buf, *trap, *bits;
	ut64 len;
	int bitlen;
	/* cannot map addr 0 */
	if (from == 0LL)
		return R_FALSE;
	if (from>to)
		return R_FALSE;
	len = to-from;
	if (len >= ST32_MAX)
		return R_FALSE;
	buf = (ut8*) malloc ((int)len);
	if (buf == NULL)
		return R_FALSE;
	trap = (ut8*) malloc ((int)len+4);
	if (trap == NULL) {
		free (buf);
		return R_FALSE;
	}
	bitlen = (len>>4)+1;
	bits = malloc (bitlen);
	if (bits == NULL) {
		free (buf);
		free (trap);
		return R_FALSE;
	}
	// TODO: check return value
	bp->iob.read_at (bp->iob.io, from, buf, len);
	memset (bits, 0x00, bitlen);
	r_bp_get_bytes (bp, trap, len, bp->endian, 0);

	trace = R_NEW (RBreakpointTrace);
	trace->addr = from;
	trace->addr_end = to;
	trace->bits = bits;
	trace->traps = trap;
	trace->buffer = buf;
	trace->length = len;
	r_list_append (bp->traces, trace);
	// read a memory, overwrite it as breakpointing area
	// everytime it is hitted, instruction is restored
	return R_TRUE;
}

R_API int r_bp_traptrace_free_at(RBreakpoint *bp, ut64 from) {
	int ret = R_FALSE;
	RListIter *iter = r_list_iterator (bp->traces);
	while (r_list_iter_next (iter)) {
		RBreakpointTrace *trace = r_list_iter_get (iter);
		if (from>=trace->addr && from<=trace->addr_end) {
			bp->iob.write_at (bp->iob.io, trace->addr,
				trace->buffer, trace->length);
			r_bp_traptrace_free (trace);
			r_list_delete (bp->traces, r_list_iter_cur (iter));
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API void r_bp_traptrace_list(RBreakpoint *bp) {
	int i;
	RListIter *iter = r_list_iterator (bp->traces);
	while (r_list_iter_next (iter)) {
		RBreakpointTrace *trace = r_list_iter_get (iter);
		for (i=0; i<trace->bitlen; i++) {
			if (BIT_CHK (trace->bits, i))
				eprintf ("  - 0x%08llx\n", trace->addr+(i<<4));
		}
	}
}

R_API int r_bp_traptrace_at(RBreakpoint *bp, ut64 from, int len) {
	int delta;
	// TODO: do we really need len?
	RListIter *iter = r_list_iterator (bp->traces);
	while (r_list_iter_next (iter)) {
		RBreakpointTrace *trace = r_list_iter_get (iter);
		if (from>=trace->addr && from+len<=trace->addr_end) {
			delta = (int) (from-trace->addr);
			if (BIT_CHK (trace->bits, delta))
			if (trace->traps[delta]==0x00)
				return R_FALSE; // already traced..debugger should stop
			BIT_SET (trace->bits, delta);
			return R_TRUE;
		}
	}
	return R_FALSE;
}
