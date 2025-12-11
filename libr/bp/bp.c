/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#include <r_bp.h>
#include <config.h>

R_LIB_VERSION (r_bp);

static struct r_bp_plugin_t *bp_static_plugins[] =
	{ R_BP_STATIC_PLUGINS };

static void r_bp_item_free(RBreakpointItem *b) {
	if (b) {
		free (b->name);
		free (b->bbytes);
		free (b->obytes);
		free (b->module_name);
		free (b->data);
		free (b->cond);
		free (b);
	}
}

R_API RBreakpoint *r_bp_new(void) {
	int i;
	RBreakpointPlugin *static_plugin;
	RBreakpoint *bp = R_NEW0 (RBreakpoint);
	bp->bps_idx_count = 16;
	bp->bps_idx = R_NEWS0 (RBreakpointItem*, bp->bps_idx_count);
	bp->stepcont = R_BP_CONT_NORMAL;
	bp->traces = r_bp_traptrace_new ();
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

// AIRPDO return void
R_API void r_bp_free(RBreakpoint *bp) {
	if (bp) {
		r_list_free (bp->bps);
		r_list_free (bp->plugins);
		r_list_free (bp->traces);
		free (bp->bps_idx);
		free (bp);
	}
}

R_API int r_bp_get_bytes(RBreakpoint *bp, ut8 *buf, int len, int endian, int idx) {
	int i;
	struct r_bp_arch_t *b;
	if (bp->cur) {
		// find matching size breakpoint
repeat:
		for (i = 0; i < bp->cur->nbps; i++) {
			b = &bp->cur->bps[i];
			if (bp->cur->bps[i].bits) {
				if (bp->bits != bp->cur->bps[i].bits) {
					continue;
				}
			}
			if (bp->cur->bps[i].length == len && bp->cur->bps[i].endian == endian) {
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
			R_LOG_WARN ("No matching bpsize");
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
	R_RETURN_VAL_IF_FAIL (bp, NULL);
	RListIter *iter;
	RBreakpointItem *b;
	r_list_foreach (bp->bps, iter, b) {
		if (b->addr == addr) {
			return b;
		}
	}
	return NULL;
}

static inline bool inRange(RBreakpointItem *b, ut64 addr) {
	return (addr >= b->addr && addr < (b->addr + b->size));
}

static inline bool matchProt(RBreakpointItem *b, int perm) {
	return (!perm || (perm && b->perm));
}

R_API RBreakpointItem *r_bp_get_in(RBreakpoint *bp, ut64 addr, int perm) {
	R_RETURN_VAL_IF_FAIL (bp, NULL);
	RBreakpointItem *b;
	RListIter *iter;
	r_list_foreach (bp->bps, iter, b) {
		// Check addr within range and provided perm matches (or null)
		if (inRange (b, addr) && matchProt (b, perm)) {
			return b;
		}
	}
	return NULL;
}

R_API RBreakpointItem *r_bp_enable(RBreakpoint *bp, ut64 addr, int set, int count) {
	R_RETURN_VAL_IF_FAIL (bp, NULL);
	RBreakpointItem *b = r_bp_get_in (bp, addr, 0);
	if (b) {
		b->enabled = set;
		b->togglehits = count;
		return b;
	}
	return NULL;
}

R_API void r_bp_enable_all(RBreakpoint *bp, int set) {
	R_RETURN_IF_FAIL (bp);
	RListIter *iter;
	RBreakpointItem *b;
	r_list_foreach (bp->bps, iter, b) {
		b->enabled = set;
	}
}

R_API int r_bp_stepy_continuation(RBreakpoint *bp) {
	R_RETURN_VAL_IF_FAIL (bp, 0);
	/* Return current step continuation mode */
	return bp->stepcont;
}

static void unlinkBreakpoint(RBreakpoint *bp, RBreakpointItem *b) {
	int i;
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (bp->bps_idx[i] == b) {
			bp->bps_idx[i] = NULL;
		}
	}
	r_list_delete_data (bp->bps, b);
}

/* TODO: detect overlapping of breakpoints */
static RBreakpointItem *r_bp_add(RBreakpoint *bp, const ut8 * R_NULLABLE obytes, ut64 addr, int size, int hw, int perm) {
	R_RETURN_VAL_IF_FAIL (bp, NULL);
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (r_bp_get_in (bp, addr, perm)) {
		R_LOG_WARN ("Breakpoint already set at this address");
		return NULL;
	}
	RBreakpointItem *b = r_bp_item_new (bp);
	if (!b) {
		return NULL;
	}
	b->addr = addr + bp->delta;
	if (bp->baddr > addr) {
		R_LOG_WARN ("base addr should not be larger than the breakpoint address");
	}
	if (bp->bpinmaps && !r_bp_is_valid (bp, b)) {
		R_LOG_WARN ("Cannot set breakpoint outside maps. Use dbg.bpinmaps to false");
	}
	b->delta = addr - bp->baddr;
	b->size = size;
	b->enabled = true;
	b->perm = perm;
	b->hw = hw;
	// NOTE: for hw breakpoints there are no bytes to save/restore
	if (!hw) {
		b->bbytes = calloc (size + 16, 1);
		if (!b->bbytes) {
			return NULL;
		}
		if (obytes) {
			b->obytes = malloc (size);
			if (!b->obytes) {
				free (b->bbytes);
				return NULL;
			}
			memcpy (b->obytes, obytes, size);
		} else {
			b->obytes = NULL;
		}
		int ret = r_bp_get_bytes (bp, b->bbytes, size, bp->endian, 0);
		if (ret != size) {
			R_LOG_WARN ("Cannot get breakpoint bytes. No architecture selected?");
		}
	}
	r_list_append (bp->bps, b);
	return b;
}

R_API void r_bp_add_fault(RBreakpoint *bp, ut64 addr, int size, int perm) {
	R_RETURN_IF_FAIL (bp);
	/* Add a fault-type breakpoint (no original bytes to preserve) */
	r_bp_add (bp, NULL, addr, size, R_BP_TYPE_FAULT, perm);
}

R_API RBreakpointItem* r_bp_add_sw(RBreakpoint *bp, ut64 addr, int size, int perm) {
	R_RETURN_VAL_IF_FAIL (bp && bp->iob.read_at, NULL);
	if (size < 1) {
		size = 1;
	}
	ut8 *bytes = calloc (1, size);
	if (!bytes) {
		return NULL;
	}
	bp->iob.read_at (bp->iob.io, addr, bytes, size);
	RBreakpointItem *item = r_bp_add (bp, bytes, addr, size, R_BP_TYPE_SW, perm);
	free (bytes);
	return item;
}

R_API RBreakpointItem* r_bp_add_hw(RBreakpoint *bp, ut64 addr, int size, int perm) {
	return r_bp_add (bp, NULL, addr, size, R_BP_TYPE_HW, perm);
}

R_API bool r_bp_del_all(RBreakpoint *bp) {
	int i;
	if (!r_list_empty (bp->bps)) {
		r_list_purge (bp->bps);
		for (i = 0; i < bp->bps_idx_count; i++) {
			bp->bps_idx[i] = NULL;
		}
		return true;
	}
	return false;
}

R_API bool r_bp_del(RBreakpoint *bp, ut64 addr) {
	RListIter *iter;
	RBreakpointItem *b;
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach (bp->bps, iter, b) {
		if (b->addr == addr) {
			unlinkBreakpoint (bp, b);
			// r_list_delete (bp->bps, iter);
			return true;
		}
	}
	return false;
}

R_API bool r_bp_set_trace(RBreakpoint *bp, ut64 addr, int set) {
	RBreakpointItem *b = r_bp_get_in (bp, addr, 0);
	if (b) {
		b->trace = set;
		return true;
	}
	return false;
}

R_API void r_bp_set_trace_all(RBreakpoint *bp, int set) {
	RListIter *iter;
	RBreakpointItem *b;
	r_list_foreach (bp->bps, iter, b) {
		b->trace = set;
	}
}

R_API char *r_bp_list(RBreakpoint *bp, int rad) {
	RBreakpointItem *b;
	RListIter *iter;
	PJ *pj = NULL;
	RStrBuf *sb = NULL;
	if (rad == 'j') {
		pj = pj_new ();
		pj_a (pj);
	} else {
		sb = r_strbuf_new ("");
	}
	r_list_foreach (bp->bps, iter, b) {
		if (pj) {
			pj_o (pj);
			pj_kN (pj, "addr", b->addr);
			pj_ki (pj, "size", b->size);
			pj_ks (pj, "perm", r_str_rwx_i (b->perm & 7)); /* filter out R_BP_PROT_ACCESS */
			pj_kb (pj, "hw", b->hw);
			pj_kb (pj, "trace", b->trace);
			pj_kb (pj, "enabled", b->enabled);
			pj_kb (pj, "valid", r_bp_is_valid (bp, b));
			pj_ks (pj, "data", r_str_get (b->data));
			pj_ks (pj, "cond", r_str_get (b->cond));
			pj_ks (pj, "name", r_str_get (b->name));
			pj_end (pj);
		} else if (rad) {
			if (b->module_name) {
				r_strbuf_appendf (sb, "dbm %s %"PFMT64d"\n", b->module_name, b->module_delta);
			} else {
				r_strbuf_appendf (sb, "db 0x%08"PFMT64x"\n", b->addr);
			}
		} else {
			r_strbuf_appendf (sb, "0x%08"PFMT64x" - 0x%08"PFMT64x \
				" %d %c%c%c %s %s %s %s cmd=\"%s\" cond=\"%s\" " \
				"name=\"%s\" module=\"%s\"\n",
				b->addr, b->addr + b->size, b->size,
				((b->perm & R_BP_PROT_READ) | (b->perm & R_BP_PROT_ACCESS)) ? 'r' : '-',
				((b->perm & R_BP_PROT_WRITE)| (b->perm & R_BP_PROT_ACCESS)) ? 'w' : '-',
				(b->perm & R_BP_PROT_EXEC) ? 'x' : '-',
				b->hw ? "hw": "sw",
				b->trace ? "trace" : "break",
				b->enabled ? "enabled" : "disabled",
				r_bp_is_valid (bp, b) ? "valid" : "invalid",
				r_str_get (b->data),
				r_str_get (b->cond),
				r_str_get (b->name),
				r_str_get (b->module_name));
		}
	}
	if (pj) {
		pj_end (pj);
		return pj_drain (pj);
	}
	return r_strbuf_drain (sb);
}

R_API RBreakpointItem *r_bp_item_new(RBreakpoint *bp) {
	int i, j;
	/* find empty slot */
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (!bp->bps_idx[i]) {
			goto return_slot;
		}
	}
	/* allocate new slot */
	bp->bps_idx_count += 16; // allocate space for 16 more bps
	RBreakpointItem **newbps = realloc (bp->bps_idx, bp->bps_idx_count * sizeof (RBreakpointItem*));
	if (newbps) {
		bp->bps_idx = newbps;
	} else {
		bp->bps_idx_count -= 16; // allocate space for 16 more bps
	}
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

R_API int r_bp_get_index_at(RBreakpoint *bp, ut64 addr) {
	int i;
	for (i = 0; i < bp->bps_idx_count; i++) {
		if (bp->bps_idx[i] && bp->bps_idx[i]->addr == addr) {
			return i;
		}
	}
	return -1;
}

R_API bool r_bp_del_index(RBreakpoint *bp, int idx) {
	if (idx >= 0 && idx < bp->bps_idx_count) {
		r_list_delete_data (bp->bps, bp->bps_idx[idx]);
		bp->bps_idx[idx] = 0;
		return true;
	}
	return false;
}

R_API int r_bp_size(RBreakpoint *bp) {
	RBreakpointArch *bpa;
	int i, bpsize = 8;
	if (!bp || !bp->cur) {
		return 0;
	}
	for (i = 0; bp->cur->bps[i].bytes; i++) {
		bpa = &bp->cur->bps[i];
		if (bpa->bits && bpa->bits != bp->bits) {
			continue;
		}
		if (bpa->length < bpsize) {
			bpsize = bpa->length;
		}
	}
	return bpsize;
}

// Check if the breakpoint is in a valid map
R_API bool r_bp_is_valid(RBreakpoint *bp, RBreakpointItem *b) {
	R_RETURN_VAL_IF_FAIL (bp && b, false);
	if (bp->bpinmaps) {
		return bp->coreb.isMapped (bp->coreb.core, b->addr, b->perm);
	}
	return true;
}
