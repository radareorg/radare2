/* radare - LGPL - Copyright 2015 - pancake */

#include <r_debug.h>

R_API RDebugSnap *r_debug_snap_new() {
	RDebugSnap *snap = R_NEW0 (RDebugSnap);
	ut64 algobit = r_hash_name_to_bits ("sha256");
	if (!snap) {
		return NULL;
	}
	snap->history = r_list_newf (r_debug_diff_free);
	snap->hash_ctx = r_hash_new (true, algobit);
	return snap;
}

R_API void r_debug_snap_free(void *p) {
	RDebugSnap *snap = (RDebugSnap *) p;
	ut32 i = 0;
	r_list_free (snap->history);
	free (snap->data);
	free (snap->comment);
	for (i = 0; i < snap->page_num; i++) {
		free (snap->hashes[i]);
	}
	free (snap->hashes);
	free (snap->last_changes);
	free (snap);
}

R_API int r_debug_snap_delete(RDebug *dbg, int idx) {
	ut32 count = 0;
	RListIter *iter;
	RDebugSnap *snap;
	if (idx == -1) {
		r_list_free (dbg->snaps);
		dbg->snaps = r_list_newf (r_debug_snap_free);
		return 1;
	}
	r_list_foreach (dbg->snaps, iter, snap) {
		if (idx != -1) {
			if (idx != count) {
				continue;
			}
		}
		r_list_delete (dbg->snaps, iter);
		count++;
		break;
	}
	return 1;
}

R_API void r_debug_snap_list(RDebug *dbg, int idx, int mode) {
	const char *comment, *comma;
	ut32 count = 0;
	RListIter *iter;
	RDebugSnap *snap;
	if (mode == 'j') {
		dbg->cb_printf ("[");
	}
	r_list_foreach (dbg->snaps, iter, snap) {
		comment = "";
		comma = (iter->n)? ",": "";
		if (idx != -1) {
			if (idx != count) {
				continue;
			}
		}
		if (snap->comment && *snap->comment) {
			comment = snap->comment;
		}
		switch (mode) {
		case 'j':
			dbg->cb_printf ("{\"count\":%d,\"addr\":%"PFMT64d ",\"size\":%d,\"history\":%d,\"comment\":\"%s\"}%s",
				count, snap->addr, snap->size, r_list_length (snap->history), comment, comma);
			break;
		case '*':
			dbg->cb_printf ("dms 0x%08"PFMT64x "\n", snap->addr);
			break;
		default:
			dbg->cb_printf ("%d 0x%08"PFMT64x " - 0x%08"PFMT64x " history: %d size: %d  --  %s\n",
				count, snap->addr, snap->addr_end, r_list_length (snap->history), snap->size, comment);
		}
		count++;
	}
	if (mode == 'j') {
		dbg->cb_printf ("]\n");
	}
}

R_API RDebugSnap *r_debug_snap_get(RDebug *dbg, ut64 addr) {
	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (dbg->snaps, iter, snap) {
		if (R_BETWEEN (snap->addr, addr, snap->addr_end - 1)) {
			return snap;
		}
	}
	return NULL;
}

R_API int r_debug_snap_set(RDebug *dbg, RDebugSnap *snap) {
	RListIter *iter;
	RDebugSnapDiff *diff;
	eprintf ("Writing %d bytes to 0x%08"PFMT64x "...\n", snap->size, snap->addr);
	/* XXX: Set all history from oldest one. It's bit ugly. */
	r_list_foreach (snap->history, iter, diff) {
		ut64 addr = snap->addr + diff->page_off * SNAP_PAGE_SIZE;
		dbg->iob.write_at (dbg->iob.io, addr, diff->data, SNAP_PAGE_SIZE);
	}
	return 1;
}

R_API int r_debug_snap_set_idx(RDebug *dbg, int idx) {
	RDebugSnap *snap;
	RListIter *iter;
	ut32 count = 0;
	if (!dbg || idx < 0) {
		return 0;
	}
	r_list_foreach (dbg->snaps, iter, snap) {
		if (count == idx) {
			r_debug_snap_set (dbg, snap);
			break;
		}
		count++;
	}
	return 1;
}

/* XXX: Just for debugging. Duplicate soon */
static void print_hash(ut8 *hash, int digest_size) {
	int i = 0;
	for (i = 0; i < digest_size; i++) {
		eprintf ("%02"PFMT64x, hash[i]);
	}
	eprintf ("\n");
}

static int r_debug_snap_map(RDebug *dbg, RDebugMap *map) {
	if (!dbg || !map || map->size < 1) {
		eprintf ("Invalid map size\n");
		return 0;
	}
	ut8 *hash;
	ut64 addr;
	ut64 algobit = r_hash_name_to_bits ("sha256");
	ut32 page_num = map->size / SNAP_PAGE_SIZE;
	int digest_size;
	/* Get an existing snapshot entry */
	RDebugSnap *snap = r_debug_snap_get (dbg, map->addr);
	if (!snap) {
		/* Create a new one */
		if (!(snap = r_debug_snap_new ())) {
			return 0;
		}
		snap->timestamp = sdb_now ();
		snap->addr = map->addr;
		snap->addr_end = map->addr_end;
		snap->size = map->size;
		snap->page_num = page_num;
		snap->data = malloc (map->size);
		if (!snap->data) {
			free (snap);
			return 0;
		}
		snap->hashes = malloc (sizeof (ut8 *) * page_num);
		snap->last_changes = calloc (page_num, sizeof (RDebugSnapDiff *));

		eprintf ("Reading %d bytes from 0x%08"PFMT64x "...\n", snap->size, snap->addr);
		dbg->iob.read_at (dbg->iob.io, snap->addr, snap->data, snap->size);

		ut32 clust_page = R_MIN (SNAP_PAGE_SIZE, snap->size);

		/* Calculate all hashes of pages */
		for (addr = snap->addr; addr < snap->addr_end; addr += SNAP_PAGE_SIZE) {
			ut32 page_off = (addr - snap->addr) / SNAP_PAGE_SIZE;
			digest_size = r_hash_calculate (snap->hash_ctx, algobit, &snap->data[addr - snap->addr], clust_page);
			hash = malloc (digest_size);
			memcpy (hash, snap->hash_ctx->digest, digest_size);
			snap->hashes[page_off] = hash;
			// eprintf ("0x%08"PFMT64x"(page: %d)...\n",addr, page_off);
			// print_hash (hash, digest_size);
		}

		r_list_append (dbg->snaps, snap);
	} else {
		/* A base snapshot have already been saved. *
		        So we only need to save different parts. */
		r_debug_diff_add (dbg, snap);
	}
	return 1;
}

R_API int r_debug_snap_all(RDebug *dbg, int perms) {
	RDebugMap *map;
	RListIter *iter;
	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if (!perms || (map->perm & perms) == perms) {
			r_debug_snap_map (dbg, map);
		}
	}
	return 0;
}

R_API int r_debug_snap(RDebug *dbg, ut64 addr) {
	RDebugMap *map = r_debug_map_get (dbg, addr);
	if (!map) {
		eprintf ("Cannot find map at 0x%08"PFMT64x "\n", addr);
		return 0;
	}
	return r_debug_snap_map (dbg, map);
}

R_API int r_debug_snap_comment(RDebug *dbg, int idx, const char *msg) {
	RDebugSnap *snap;
	RListIter *iter;
	ut32 count = 0;
	if (!dbg || idx < 0 || !msg || !*msg) {
		return 0;
	}
	r_list_foreach (dbg->snaps, iter, snap) {
		if (count == idx) {
			free (snap->comment);
			snap->comment = strdup (r_str_trim_const (msg));
			break;
		}
		count++;
	}
	return 1;
}

R_API void r_debug_diff_free(void *p) {
	RDebugSnapDiff *diff = (RDebugSnapDiff *) p;
	free (diff->data);
	free (diff);
}

R_API void r_debug_diff_add(RDebug *dbg, RDebugSnap *base) {
	RDebugSnapDiff *last, *new;
	ut64 addr;
	int digest_size;
	ut32 page_off;
	ut64 algobit = r_hash_name_to_bits ("sha256");
	ut32 clust_page = R_MIN (SNAP_PAGE_SIZE, base->size);

	/* Compare hash of pages. */
	for (addr = base->addr; addr < base->addr_end; addr += SNAP_PAGE_SIZE) {
		ut8 *prev_hash, *cur_hash;
		ut8 *buf = malloc (clust_page);
		/* Copy current memory value to buf and calculate cur_hash from it. */
		dbg->iob.read_at (dbg->iob.io, addr, buf, clust_page);
		digest_size = r_hash_calculate (base->hash_ctx, algobit, buf, clust_page);
		cur_hash = base->hash_ctx->digest;

		page_off = (addr - base->addr) / SNAP_PAGE_SIZE;
		/* Check If there is any last change for this page. */
		if ((last = base->last_changes[page_off])) {
			/* Use hash of last SnapDiff */
			// eprintf ("found diff\n");
			prev_hash = last->hash;
		} else {
			/* Use hash of base snapshot */
			// eprintf ("use base\n");
			prev_hash = base->hashes[page_off];
		}
		/* Memory has been changed. So add new diff entry for this addr */
		if (memcmp (cur_hash, prev_hash, digest_size) != 0) {
			// eprintf ("different: 0x%08"PFMT64x"(page %d)...\n", addr, page_off);
			// print_hash (cur_hash, digest_size);
			// print_hash (prev_hash, digest_size);
			/* Create new diff entry, save one page and calculate hash. */
			new = (RDebugSnapDiff *) malloc (sizeof (RDebugSnapDiff));
			new->page_off = page_off;
			new->data = buf;
			memcpy (new->hash, cur_hash, digest_size);

			r_list_append (base->history, new);
			base->last_changes[page_off] = new;
		}
	}
}
