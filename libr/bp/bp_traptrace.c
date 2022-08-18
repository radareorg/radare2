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

R_API RList *r_bp_traptrace_new(void) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = &r_bp_traptrace_free;
	return list;
}

R_API void r_bp_traptrace_enable(RBreakpoint *bp, int enable) {
	RListIter *iter;
	RBreakpointTrace *trace;
	r_list_foreach (bp->traces, iter, trace) {
		ut8 *buf = (enable)?trace->traps:trace->buffer;
		bp->iob.write_at (bp->iob.io, trace->addr, buf, trace->length);
	}
}

R_API void r_bp_traptrace_reset(RBreakpoint *bp, int hard) {
	RListIter *iter;
	RBreakpointTrace *trace;
	r_list_foreach (bp->traces, iter, trace) {
		if (hard) {
			r_bp_traptrace_free (trace);
			// XXX: This segfaults
			//r_list_delete (bp->traces, r_list_iter_cur (iter));
		} else {
			memset (trace->bits, 0x00, trace->bitlen);
		}
	}
	if (hard) {
		// XXX: traces not freed correctly (memleak)
		bp->traces = r_list_new ();
		bp->traces->free = r_bp_traptrace_free;
	}
}

// FIX: efficiency
R_API ut64 r_bp_traptrace_next(RBreakpoint *bp, ut64 addr) {
	int i, delta;
	RListIter *iter;
	RBreakpointTrace *trace;
	r_list_foreach (bp->traces, iter, trace) {
		if (addr>=trace->addr && addr<=trace->addr_end) {
			delta = (int)(addr-trace->addr);
			for (i = delta; i < trace->length; i++) {
				if (R_BIT_CHK (trace->bits, i)) {
					return addr + i;
				}
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
	if (from == 0LL) {
		return false;
	}
	if (from > to) {
		return false;
	}
	len = to-from;
	if (len >= ST32_MAX) {
		return false;
	}
	buf = (ut8*) malloc ((int)len);
	if (!buf) {
		return false;
	}
	trap = (ut8*) malloc ((int)len+4);
	if (!trap) {
		free (buf);
		return false;
	}
	bitlen = (len>>4)+1;
	bits = malloc (bitlen);
	if (!bits) {
		free (buf);
		free (trap);
		return false;
	}
	// TODO: check return value
	bp->iob.read_at (bp->iob.io, from, buf, len);
	memset (bits, 0x00, bitlen);
	r_bp_get_bytes (bp, trap, len, bp->endian, 0);

	trace = R_NEW (RBreakpointTrace);
	if (!trace) {
		free (buf);
		free (trap);
		free (bits);
		return false;
	}
	trace->addr = from;
	trace->addr_end = to;
	trace->bits = bits;
	trace->traps = trap;
	trace->buffer = buf;
	trace->length = len;
	if (!r_list_append (bp->traces, trace)) {
		free (buf);
		free (trap);
		free (trace);
		return false;
	}
	// read a memory, overwrite it as breakpointing area
	// every time it is hitted, instruction is restored
	return true;
}

R_API int r_bp_traptrace_free_at(RBreakpoint *bp, ut64 from) {
	int ret = false;
	RListIter *iter, *iter_tmp;
	RBreakpointTrace *trace;
	r_list_foreach_safe (bp->traces, iter, iter_tmp, trace) {
		if (from>=trace->addr && from<=trace->addr_end) {
			bp->iob.write_at (bp->iob.io, trace->addr,
				trace->buffer, trace->length);
			r_bp_traptrace_free (trace);
			r_list_delete (bp->traces, iter);
			ret = true;
		}
	}
	return ret;
}

R_API void r_bp_traptrace_list(RBreakpoint *bp) {
	int i;
	RListIter *iter;
	RBreakpointTrace *trace;
	r_list_foreach (bp->traces, iter, trace) {
		for (i = 0; i < trace->bitlen; i++) {
			if (R_BIT_CHK (trace->bits, i)) {
				eprintf ("  - 0x%08" PFMT64x "\n", trace->addr + (i << 4));
			}
		}
	}
}

R_API int r_bp_traptrace_at(RBreakpoint *bp, ut64 from, int len) {
	int delta;
	RListIter *iter;
	RBreakpointTrace *trace;
	r_list_foreach (bp->traces, iter, trace) {
	// TODO: do we really need len?
		if (from>=trace->addr && from+len<=trace->addr_end) {
			delta = (int) (from-trace->addr);
			if (R_BIT_CHK (trace->bits, delta)) {
				if (trace->traps[delta] == 0x00) {
					return false; // already traced..debugger should stop
				}
			}
			R_BIT_SET (trace->bits, delta);
			return true;
		}
	}
	return false;
}
