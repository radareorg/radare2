/* radare2 - LGPL - Copyright 2009-2015 - pancake */

#include <r_bp.h>
#include "../config.h"

R_LIB_VERSION (r_bp);

static struct r_bp_plugin_t *bp_static_plugins[] =
	{ R_BP_STATIC_PLUGINS };

static void r_bp_item_free (RBreakpointItem *b) {
	free (b->name);
	free (b->bbytes);
	free (b->obytes);
	free (b->module_name);
	free (b);
}

R_API RBreakpoint *r_bp_new() {
	RBreakpoint *bp = R_NEW0 (RBreakpoint);
	RBreakpointPlugin *static_plugin;
	int i;
	if (!bp) return NULL;
	bp->bps_idx_count = 16;
	bp->bps_idx = R_NEWS0 (RBreakpointItem*, bp->bps_idx_count);
	bp->stepcont = R_BP_CONT_NORMAL;
	bp->traces = r_bp_traptrace_new ();
	bp->cb_printf = (PrintfCallback)printf;
	bp->bps = r_list_newf ((RListFree)r_bp_item_free);
	bp->plugins = r_list_newf ((RListFree)free);
	for (i = 0; bp_static_plugins[i]; i++) {
		static_plugin = R_NEW (RBreakpointPlugin);
		memcpy (static_plugin, bp_static_plugins[i],
			sizeof (RBreakpointPlugin));
		r_bp_plugin_add (bp, static_plugin);
	}
	memset (&bp->iob, 0, sizeof (bp->iob));
	return bp;
}

R_API RBreakpoint *r_bp_free(RBreakpoint *bp) {
	r_list_free (bp->bps);
	r_list_free (bp->plugins);
	r_list_free (bp->traces);
	free (bp->bps_idx);
	free (bp);
	return NULL;
}

R_API int r_bp_get_bytes(RBreakpoint *bp, ut8 *buf, int len, int endian, int idx) {
	int i;
	struct r_bp_arch_t *b;
	if (bp->cur) {
		// find matching size breakpoint
repeat:
		for (i=0; i< bp->cur->nbps; i++) {
			b = &bp->cur->bps[i];
			if (bp->cur->bps[i].bits) {
				if (bp->bits != bp->cur->bps[i].bits)
					continue;
			}
			if (bp->cur->bps[i].length == len) {
				memcpy (buf, b->bytes, b->length);
				return b->length;
			}
		}
		if (len != 4) {
			len = 4;
			goto repeat;
		}
		/* if not found try to pad with the first one */
		b = &bp->cur->bps[0];
		if (len % b->length) {
			eprintf ("No matching bpsize\n");
			return 0;
		}
		for (i = 0; i < len; i++) {
			memcpy (buf + i, b->bytes, b->length);
		}
		return b->length;
	}
	return 0;
}

R_API RBreakpointItem *r_bp_get_at(RBreakpoint *bp, ut64 addr) {
	RListIter *iter;
	RBreakpointItem *b;
	r_list_foreach(bp->bps, iter, b) {
		if (b->addr == addr)
			return b;
	}
	return NULL;
}

static inline bool inRange(RBreakpointItem *b, ut64 addr) {
	return (addr >= b->addr && addr < (b->addr + b->size));
}

static inline bool matchProt(RBreakpointItem *b, int rwx) {
	return (!rwx || (rwx && b->rwx));
}

R_API RBreakpointItem *r_bp_get_in(RBreakpoint *bp, ut64 addr, int rwx) {
	RBreakpointItem *b;
	RListIter *iter;
	r_list_foreach (bp->bps, iter, b) {
		// eprintf ("---ataddr--- 0x%08"PFMT64x" %d %d %x\n", b->addr, b->size, b->recoil, b->rwx);
		// Check addr within range and provided rwx matches (or null)
		if (inRange (b, addr) && matchProt (b, rwx)) {
			return b;
		}
	}
	return NULL;
}

R_API RBreakpointItem *r_bp_enable(RBreakpoint *bp, ut64 addr, int set) {
	RBreakpointItem *b = r_bp_get_in (bp, addr, 0);
	if (b) {
		b->enabled = set;
		return b;
	}
	return NULL;
}

R_API int r_bp_enable_all(RBreakpoint *bp, int set) {
	RListIter *iter;
	RBreakpointItem *b;
	r_list_foreach (bp->bps, iter, b) {
		b->enabled = set;
	}
	return true;
}

R_API int r_bp_stepy_continuation(RBreakpoint *bp) {
	// TODO: implement
	return bp->stepcont;
}

/* TODO: detect overlapping of breakpoints */
static RBreakpointItem *r_bp_add(RBreakpoint *bp, const ut8 *obytes, ut64 addr, int size, int hw, int rwx) {
	int ret;
	RBreakpointItem *b;
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (r_bp_get_in (bp, addr, rwx)) {
		eprintf ("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = r_bp_item_new (bp);
	b->addr = addr + bp->delta;
	b->size = size;
	b->enabled = true;
	b->rwx = rwx;
	b->hw = hw;
	if (!hw) {
		b->bbytes = calloc (size + 16, 1);
		if (obytes) {
			b->obytes = malloc (size);
			memcpy (b->obytes, obytes, size);
		} else {
			b->obytes = NULL;
		}
		/* XXX: endian .. use bp->endian */
		// XXX for hw breakpoints there are no bytes
		ret = r_bp_get_bytes (bp, b->bbytes, size, 0, 0);
		if (ret != size) {
			eprintf ("Cannot get breakpoint bytes. No r_bp_use()?\n"); //XXX(jjd): what is r_bp_use ?
			r_bp_item_free (b);
			return NULL;
		}
		b->recoil = ret;
	}
	bp->nbps++;
	r_list_append (bp->bps, b);
	return b;
}

R_API int r_bp_add_fault(RBreakpoint *bp, ut64 addr, int size, int rwx) {
	// TODO
	return false;
}

R_API RBreakpointItem* r_bp_add_sw(RBreakpoint *bp, ut64 addr, int size, int rwx) {
	RBreakpointItem *item;
	ut8 *bytes;
	if (size < 1) {
		size = 1;
	}
	if (!(bytes = calloc (1, size))) {
		return NULL;
	}
	memset (bytes, 0, size);
	if (bp->iob.read_at) {
		bp->iob.read_at (bp->iob.io, addr, bytes, size);
	}
	item = r_bp_add (bp, bytes, addr, size, R_BP_TYPE_SW, rwx);
	free (bytes);
	return item;
}

R_API RBreakpointItem* r_bp_add_hw(RBreakpoint *bp, ut64 addr, int size, int rwx) {
	return r_bp_add (bp, NULL, addr, size, R_BP_TYPE_HW, rwx);
}

R_API int r_bp_del_all(RBreakpoint *bp) {
	if (!r_list_empty (bp->bps)) {
		r_list_purge (bp->bps);
		return true;
	}
	return false;
}

R_API int r_bp_del(RBreakpoint *bp, ut64 addr) {
	RListIter *iter;
	RBreakpointItem *b;
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach (bp->bps, iter, b) {
		if (b->addr == addr) {
			r_list_delete (bp->bps, iter);
			return true;
		}
	}
	return false;
}

R_API int r_bp_set_trace(RBreakpoint *bp, ut64 addr, int set) {
	RBreakpointItem *b = r_bp_get_in (bp, addr, 0);
	if (b) {
		b->trace = set;
		return true;
	}
	return false;
}

R_API int r_bp_set_trace_all(RBreakpoint *bp, int set) {
	RListIter *iter;
	RBreakpointItem *b;
	r_list_foreach (bp->bps, iter, b) {
		b->trace = set;
	}
	return true;
}
// TODO: deprecate
R_API int r_bp_list(RBreakpoint *bp, int rad) {
	int n = 0;
	RBreakpointItem *b;
	RListIter *iter;
	if (rad == 'j') bp->cb_printf ("[");
	//eprintf ("Breakpoint list:\n");
	r_list_foreach (bp->bps, iter, b) {
		switch (rad) {
		case 0:
			bp->cb_printf ("0x%08"PFMT64x" - 0x%08"PFMT64x \
				" %d %c%c%c %s %s %s cmd=\"%s\" " \
				"name=\"%s\" module=\"%s\"\n",
				b->addr, b->addr + b->size, b->size,
				(b->rwx & R_BP_PROT_READ) ? 'r' : '-',
				(b->rwx & R_BP_PROT_WRITE) ? 'w' : '-',
				(b->rwx & R_BP_PROT_EXEC) ? 'x' : '-',
				b->hw ? "hw": "sw",
				b->trace ? "trace" : "break",
				b->enabled ? "enabled" : "disabled",
				b->data ? b->data : "",
				b->name ? b->name : "",
				b->module_name ? b->module_name : "");
			break;
		case 1:
		case 'r':
		case '*':
			// TODO: add command, tracing, enable, ..
			if (b->module_name) {
			    	bp->cb_printf ("dbm %s %"PFMT64d"\n", b->module_name, b->module_delta);
			} else { 
				bp->cb_printf ("db 0x%08"PFMT64x"\n", b->addr);
			}
			//b->trace? "trace": "break",
			//b->enabled? "enabled": "disabled",
			// b->data? b->data: "");
			break;
		case 'j':
			bp->cb_printf ("%s{\"addr\":%"PFMT64d",\"size\":%d,"
				"\"prot\":\"%c%c%c\",\"hw\":%s,"
				"\"trace\":%s,\"enabled\":%s,"
				"\"data\":\"%s\"}",
				iter->p ? "," : "",
				b->addr, b->size,
				(b->rwx & R_BP_PROT_READ) ? 'r' : '-',
				(b->rwx & R_BP_PROT_WRITE) ? 'w' : '-',
				(b->rwx & R_BP_PROT_EXEC) ? 'x' : '-',
				b->hw ? "true" : "false",
				b->trace ? "true" : "false",
				b->enabled ? "true" : "false",
				b->data ? b->data : "");
			break;
		}
		/* TODO: Show list of pids and trace points, conditionals */
		n++;
	}
	if (rad == 'j') {
		bp->cb_printf ("]\n");
	}
	return n;
}

R_API RBreakpointItem *r_bp_item_new (RBreakpoint *bp) {
	int i, j;
	/* find empty slot */
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (!bp->bps_idx[i]) {
			goto return_slot;
		}
	}
	/* allocate new slot */
	bp->bps_idx_count += 16; // alocate space for 16 more bps
	bp->bps_idx = realloc (bp->bps_idx, bp->bps_idx_count * sizeof(RBreakpointItem*));
	for (j = i; j < bp->bps_idx_count; j++) {
		bp->bps_idx[j] = NULL;
	}
return_slot:
	/* empty slot */
	return (bp->bps_idx[i] = R_NEW0 (RBreakpointItem));
}

R_API RBreakpointItem *r_bp_get_index(RBreakpoint *bp, int idx) {
	if (idx >= 0 && idx < bp->bps_idx_count) {
		return bp->bps_idx[idx];
	}
	return NULL;
}

R_API int r_bp_del_index(RBreakpoint *bp, int idx) {
	if (idx >= 0 && idx < bp->bps_idx_count) {
		r_list_delete_data (bp->bps, bp->bps_idx[idx]);
		free (bp->bps_idx[idx]);
		bp->bps_idx[idx] = NULL;
		return true;
	}
	return false;
}
