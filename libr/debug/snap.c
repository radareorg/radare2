/* radare - LGPL - Copyright 2015-2017 - pancake, rkx1209 */

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
	r_list_free (snap->history);
	free (snap->data);
	free (snap->comment);
	free (snap->hashes);
	free (snap);
}

R_API int r_debug_snap_delete(RDebug *dbg, int idx) {
	ut32 count = 0;
	RListIter *iter;
	if (idx == -1) {
		r_list_free (dbg->snaps);
		dbg->snaps = r_list_newf (r_debug_snap_free);
		return 1;
	}
	r_list_foreach_iter (dbg->snaps, iter) {
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

static RDebugSnap *r_debug_snap_get_map(RDebug *dbg, RDebugMap *map) {
	RListIter *iter;
	RDebugSnap *snap;
	if (dbg && map) {
		r_list_foreach (dbg->snaps, iter, snap) {
			if (snap->addr <= map->addr && map->addr_end <= snap->addr_end) {
				return snap;
			}
		}
	}
	return NULL;
}

R_API RDebugSnap *r_debug_snap_get(RDebug *dbg, ut64 addr) {
	RDebugMap *map = r_debug_map_get (dbg, addr);
	return r_debug_snap_get_map (dbg, map);
}

static void r_page_data_set(RDebug *dbg, RPageData *page) {
	RDebugSnapDiff *diff = page->diff;
	ut64 addr = diff->base->addr + page->page_off * SNAP_PAGE_SIZE;
	dbg->iob.write_at (dbg->iob.io, addr, page->data, SNAP_PAGE_SIZE);
}

/* snap->history must have at least one entry */
R_API void r_debug_diff_set(RDebug *dbg, RDebugSnapDiff *diff) {
	RPageData *prev_page, *last_page;
	RDebugSnap *snap = diff->base;
	RDebugMap *cur_map = r_debug_map_get (dbg, snap->addr + 1);
	RDebugSnapDiff *latest;
	ut64 addr;
	ut32 page_off;

	/* Save current snapshot. It is marked as a finish point of reverse execution */
	latest = r_debug_snap_map (dbg, cur_map);
	if (!latest) {
		return;
	}

	//eprintf ("Apply diff [0x%08"PFMT64x ", 0x%08"PFMT64x "]\n", snap->addr, snap->addr_end);

	/* Roll back page datas that's been changed **after** specified SnapDiff 'diff' */
	for (addr = snap->addr; addr < snap->addr_end; addr += SNAP_PAGE_SIZE) {
		page_off = (addr - snap->addr) / SNAP_PAGE_SIZE;
		prev_page = diff->last_changes[page_off];
		/* Roll back only latest page, that's been changed after prev_page */
		if ((last_page = latest->last_changes[page_off]) && !prev_page) {
			ut64 off = (ut64) last_page->page_off * SNAP_PAGE_SIZE;
			/* Copy a page data of base snap to current addr. (i.e. roll back) */
			dbg->iob.write_at (dbg->iob.io, addr, snap->data + off, SNAP_PAGE_SIZE);
			//eprintf ("Roll back 0x%08"PFMT64x "(page: %d)\n", addr, page_off);
		}
	}

	/* Set all previous history (including specified SnapDiff 'diff')*/
	for (addr = snap->addr; addr < snap->addr_end; addr += SNAP_PAGE_SIZE) {
		page_off = (addr - snap->addr) / SNAP_PAGE_SIZE;
		if ((prev_page = diff->last_changes[page_off])) {
			r_page_data_set (dbg, prev_page);
			//eprintf ("Update 0x%08"PFMT64x "(page: %d)\n", addr, page_off);
		}
	}
	r_list_pop (snap->history);
	r_debug_diff_free (latest);
}

/* Roll back to base snapshot */
R_API void r_debug_diff_set_base(RDebug *dbg, RDebugSnap *base) {
	RPageData *last_page;
	RDebugMap *cur_map = r_debug_map_get (dbg, base->addr + 1);
	RDebugSnapDiff *latest;
	ut64 addr;
	ut32 page_off;

	/* Save current snapshot. It is marked as a finish point of reverse execution */
	latest = r_debug_snap_map (dbg, cur_map);
	if (!latest) {
		return;
	}

	//eprintf ("Roll back to base [0x%08"PFMT64x ", 0x%08"PFMT64x "]\n", cur_map->addr, cur_map->addr_end);

	for (addr = base->addr; addr < base->addr_end; addr += SNAP_PAGE_SIZE) {
		page_off = (addr - base->addr) / SNAP_PAGE_SIZE;
		if ((last_page = latest->last_changes[page_off])) {
			ut64 off = (ut64) last_page->page_off * SNAP_PAGE_SIZE;
			/* Copy a page data of base snap to current addr. (i.e. roll back) */
			dbg->iob.write_at (dbg->iob.io, addr, base->data + off, SNAP_PAGE_SIZE);
			//eprintf ("Roll back 0x%08"PFMT64x "(page: %d)\n", addr, page_off);
		}
	}

	r_list_pop (base->history);
	r_debug_diff_free (latest);
}

// XXX: snap_set will be duplicated soon
R_API int r_debug_snap_set(RDebug *dbg, RDebugSnap *snap) {
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
#if 0
static void print_hash(ut8 *hash, int digest_size) {
	int i = 0;
	for (i = 0; i < digest_size; i++) {
		eprintf ("%02"PFMT32x, hash[i]);
	}
	eprintf ("\n");
}
#endif

R_API RDebugSnapDiff *r_debug_snap_map(RDebug *dbg, RDebugMap *map) {
	if (!dbg || !map || map->size < 1) {
		eprintf ("Invalid map size\n");
		return NULL;
	}
	ut8 *hash;
	ut64 addr;
	ut64 algobit = r_hash_name_to_bits ("sha256");
	ut32 page_num = map->size / SNAP_PAGE_SIZE;
	ut32 digest_size;
	/* Get an existing snapshot entry */
	RDebugSnap *snap = r_debug_snap_get_map (dbg, map);
	if (!snap) {
		/* Create a new one */
		if (!(snap = r_debug_snap_new ())) {
			return NULL;
		}
		snap->timestamp = sdb_now ();
		snap->addr = map->addr;
		snap->addr_end = map->addr_end;
		snap->size = map->size;
		snap->page_num = page_num;
		snap->data = malloc (map->size);
		snap->perm = map->perm;
		if (!snap->data) {
			goto error;
		}
		snap->hashes = R_NEWS0 (ut8 *, page_num);
		if (!snap->hashes) {
			free (snap->data);
			goto error;
		}
		eprintf ("Reading %d byte(s) from 0x%08"PFMT64x "...\n", snap->size, snap->addr);
		dbg->iob.read_at (dbg->iob.io, snap->addr, snap->data, snap->size);

		ut32 clust_page = R_MIN (SNAP_PAGE_SIZE, snap->size);

		/* Calculate all hashes of pages */
		for (addr = snap->addr; addr < snap->addr_end; addr += SNAP_PAGE_SIZE) {
			ut32 page_off = (addr - snap->addr) / SNAP_PAGE_SIZE;
			digest_size = r_hash_calculate (snap->hash_ctx, algobit, &snap->data[addr - snap->addr], clust_page);
			hash = calloc (128, 1);	// Fix hash size to 128 byte
			memcpy (hash, snap->hash_ctx->digest, digest_size);
			snap->hashes[page_off] = hash;
			// eprintf ("0x%08"PFMT64x"(page: %d)...\n",addr, page_off);
			// print_hash (hash, digest_size);
		}

		r_list_append (dbg->snaps, snap);
		goto okay;
	} else {
		/* A base snapshot have already been saved. *
		        So we only need to save different parts. */
		return r_debug_diff_add (dbg, snap);
	}
error:
	free (snap);
okay:
	return NULL;
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
	if (!r_debug_snap_map (dbg, map)) {
		return 0;
	}
	return 1;
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
			snap->comment = strdup (r_str_trim_head_ro (msg));
			break;
		}
		count++;
	}
	return 1;
}

R_API void r_page_data_free(void *p) {
	RPageData *page = (RPageData *) p;
	free (page->data);
	free (page);
}

R_API void r_debug_diff_free(void *p) {
	RDebugSnapDiff *diff = (RDebugSnapDiff *) p;
	r_list_free (diff->pages);
	free (diff->last_changes);
	free (diff);
}

R_API RDebugSnapDiff *r_debug_diff_add(RDebug *dbg, RDebugSnap *base) {
	RDebugSnapDiff *prev_diff = NULL, *new_diff;
	RPageData *new_page, *last_page;
	ut64 addr;
	int digest_size;
	ut32 page_off;
	ut64 algobit = r_hash_name_to_bits ("sha256");
	ut32 clust_page = R_MIN (SNAP_PAGE_SIZE, base->size);

	new_diff = R_NEW0 (RDebugSnapDiff);
	if (!new_diff) {
		goto error;
	}
	new_diff->base = base;
	new_diff->pages = r_list_newf (r_page_data_free);
	new_diff->last_changes = R_NEWS0 (RPageData *, base->page_num);
	if (r_list_length (base->history)) {
		/* Inherit last changes from previous SnapDiff */
		RListIter *tail = r_list_tail (base->history);
		if (tail) {
			prev_diff = (RDebugSnapDiff *) tail->data;
			memcpy (new_diff->last_changes, prev_diff->last_changes, sizeof (RPageData *) * base->page_num);
		}
	}

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
		if (prev_diff && (last_page = prev_diff->last_changes[page_off])) {
			/* Use hash of last SnapDiff */
			// eprintf ("use hash of diff\n");
			prev_hash = last_page->hash;
		} else {
			/* Use hash of base snapshot */
			// eprintf ("use hash of base\n");
			prev_hash = base->hashes[page_off];
		}
		/* Memory has been changed. So add new diff entry for this addr */
		if (memcmp (cur_hash, prev_hash, digest_size) != 0) {
			// print_hash (cur_hash, digest_size);
			// print_hash (prev_hash, digest_size);
			/* Create new page diff entry, save one page and calculate hash. */
			new_page = R_NEW0 (RPageData);
			new_page->diff = new_diff;
			new_page->page_off = page_off;
			new_page->data = buf;
			memcpy (new_page->hash, cur_hash, digest_size);
			new_diff->last_changes[page_off] = new_page;	// Update last change to new page
			r_list_append (new_diff->pages, new_page);
		}
	}
	if (r_list_length (new_diff->pages)) {
#if 0
		RPageData *page;
		RListIter *iter;
		eprintf ("saved: 0x%08"PFMT64x "(page: ", base->addr);
		r_list_foreach (new_diff->pages, iter, page) {
			eprintf ("%d ", page->page_off);
		}
		eprintf (")\n");
#endif
		r_list_append (base->history, new_diff);
		return new_diff;
	} else {
		r_debug_diff_free (new_diff);
		return NULL;
	}
error:
	free (new_diff);
	return NULL;
}
