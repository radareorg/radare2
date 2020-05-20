/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <r_debug.h>

R_API void r_debug_session_free(void *p) {
	RDebugSession *session = (RDebugSession *) p;
	free (session->comment);
	free (session);
}

static int r_debug_session_lastid(RDebug *dbg) {
	return r_list_length (dbg->sessions);
}

R_API void r_debug_session_list(RDebug *dbg) {
	ut32 count = 0;
	RListIter *iterse, *itersn, *iterpg;
	RDebugSnap *snap;
	RDebugSnapDiff *diff;
	RDebugSession *session;
	RPageData *page;

	r_list_foreach (dbg->sessions, iterse, session) {
		count = 0;
		dbg->cb_printf ("session:%2d   at:0x%08"PFMT64x "   \"%s\"\n", session->key.id, session->key.addr, session->comment);
		r_list_foreach (session->memlist, itersn, diff) {
			snap = diff->base;
			dbg->cb_printf ("  - %d 0x%08"PFMT64x " - 0x%08"PFMT64x " size: %d ",
				count, snap->addr, snap->addr_end, snap->size);
			dbg->cb_printf ("(pages: ");
			r_list_foreach (diff->pages, iterpg, page) {
				dbg->cb_printf ("%d ", page->page_off);
			}
			dbg->cb_printf (")\n");
			count++;
		}
	}
}

R_API RDebugSession *r_debug_session_add(RDebug *dbg, RListIter **tail) {
	RDebugSession *session;
	RDebugSnapDiff *diff;
	RListIter *iter;
	RDebugMap *map;
	ut64 addr;
	int i, perms = R_PERM_RW;

	addr = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	/* Session has already existed at this addr? */
	r_list_foreach (dbg->sessions, iter, session) {
		if (session->key.addr == addr) {
			if (tail) {
				*tail = iter;
			}
			return session;
		}
	}

	session = R_NEW0 (RDebugSession);
	if (!session) {
		return NULL;
	}

	session->key = (RDebugKey) {
		addr, r_debug_session_lastid (dbg)
	};
	session->comment = r_str_new ("");

	/* save current registers */
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		session->reg[i] = r_list_tail (dbg->reg->regset[i].pool);
	}
	r_reg_arena_push (dbg->reg);

	/* save memory snapshots */
	session->memlist = r_list_newf ((RListFree)r_debug_diff_free);

	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if (!perms || (map->perm & perms) == perms) {
			diff = r_debug_snap_map (dbg, map);
			if (diff) {
				/* Add diff history */
				r_list_append (session->memlist, diff);
			}
		}
	}

	r_list_append (dbg->sessions, session);
	if (tail) {
		*tail = dbg->sessions->tail;
	}
	return session;
}

R_API bool r_debug_session_delete(RDebug *dbg, int idx) {
	RListIter *iter;
	RDebugSession *session;
	if (idx == -1) {
		r_list_free (dbg->sessions);
		dbg->sessions = r_list_newf ((RListFree)r_debug_session_free);
		return true;
	}
	r_list_foreach (dbg->sessions, iter, session) {
		if (session->key.id == idx) {
			r_list_delete (dbg->sessions, iter);
			return true;
		}
	}
	return false;
}

R_API bool r_debug_session_comment(RDebug *dbg, int idx, const char *msg) {
	RDebugSession *session;
	RListIter *iter;
	ut32 count = 0;
	if (!dbg || idx < 0 || !msg || !*msg) {
		return false;
	}
	r_list_foreach (dbg->sessions, iter, session) {
		if (count == idx) {
			if (session->comment) {
				free (session->comment);
			}
			session->comment = strdup (r_str_trim_head_ro (msg));
			break;
		}
		count++;
	}
	return true;
}

static void r_debug_session_set_registers(RDebug *dbg, RDebugSession *session) {
	RRegArena *arena;
	RListIter *iterr;
	int i;
	/* Restore all register values from the stack area pointed by session */
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		iterr = session->reg[i];
		arena = iterr->data;
		if (dbg->reg->regset[i].arena->bytes) {
			memcpy (dbg->reg->regset[i].arena->bytes, arena->bytes, arena->size);
		}
	}
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 1);
}

static void r_debug_session_set_diff(RDebug *dbg, RDebugSession *session) {
	RListIter *iter;
	RDebugSnapDiff *diff;
	r_debug_session_set_registers (dbg, session);
	/* Restore all memory values from memory (diff) snapshots */
	r_list_foreach (session->memlist, iter, diff) {
		r_debug_diff_set (dbg, diff);
	}
}

static void r_debug_session_set_base(RDebug *dbg, RDebugSession *before) {
	RListIter *iter;
	RDebugSnap *snap;
	r_debug_session_set_registers (dbg, before);
	/* Restore all memory values from base memory snapshots */
	r_list_foreach (dbg->snaps, iter, snap) {
		r_debug_diff_set_base (dbg, snap);
	}
}

R_API void r_debug_session_set(RDebug *dbg, RDebugSession *before) {
	if (!r_list_length (before->memlist)) {
		/* Diff list is empty. (i.e. Before session is base snapshot) *
		         So set base memory snapshot */
		r_debug_session_set_base (dbg, before);
	} else {
		r_debug_session_set_diff (dbg, before);
	}
}

R_API bool r_debug_session_set_idx(RDebug *dbg, int idx) {
	RDebugSession *session;
	RListIter *iter;
	ut32 count = 0;

	if (!dbg || idx < 0) {
		return false;
	}
	r_list_foreach (dbg->sessions, iter, session) {
		if (session->key.id == idx) {
			r_debug_session_set (dbg, session);
			return true;
		}
		count++;
	}
	return false;
}

/* Get most recent used session at the time */
R_API RDebugSession *r_debug_session_get(RDebug *dbg, RListIter *tail) {
	RDebugSession *session;
	if (!tail) {
		return NULL;
	}
	session = (RDebugSession *) tail->data;
	return session;
}

/* XXX: bit ugly... :( )*/
static ut32 r_snap_to_idx(RDebug *dbg, RDebugSnap *snap) {
	RListIter *iter;
	RDebugSnap *s;
	ut32 base_idx = 0;
	r_list_foreach (dbg->snaps, iter, s) {
		if (snap == s) {
			break;
		}
		base_idx++;
	}
	return base_idx;
}

static RDebugSnap *r_idx_to_snap(RDebug *dbg, ut32 idx) {
	RListIter *iter;
	RDebugSnap *s;
	ut32 base_idx = 0;
	r_list_foreach (dbg->snaps, iter, s) {
		if (base_idx == idx) {
			return s;
		}
		base_idx++;
	}
	return NULL;
}

R_API void r_debug_session_path(RDebug *dbg, const char *path) {
	R_FREE (dbg->snap_path);
	dbg->snap_path =  r_file_abspath (path);
}

R_API void r_debug_session_save(RDebug *dbg, const char *file) {
	RListIter *iter, *iter2, *iter3;
	RDebugSession *session;
	RDebugSnap *base;
	RDebugSnapDiff *snapdiff;
	RPageData *page;

	RSessionHeader header;
	RDiffEntry diffentry;
	RSnapEntry snapentry;

	ut32 i;
	const char *path = dbg->snap_path;
	if (!r_file_is_directory (path)) {
		eprintf ("%s is not correct path\n", path);
		return;
	}
	char *base_file = r_str_newf ("%s/%s.dump", path, file);
	char *diff_file = r_str_newf ("%s/%s.session", path, file);

	if (!base_file) {
		free (diff_file);
		return;
	}

	if (!diff_file) {
		free (base_file);
		return;
	}

	/* dump all base snapshots */
	r_list_foreach (dbg->snaps, iter, base) {
		snapentry.addr = base->addr;
		snapentry.size = base->size;
		snapentry.timestamp = base->timestamp;
		snapentry.perm = base->perm;
		r_file_dump (base_file, (const ut8 *) &snapentry, sizeof (RSnapEntry), 1);
		r_file_dump (base_file, (const ut8 *) base->data, base->size, 1);
		/* dump all hashes */
		for (i = 0; i < base->page_num; i++) {
			r_file_dump (base_file, (const ut8 *) base->hashes[i], 128, 1);
		}
	}

	/* dump all sessions */
	r_list_foreach (dbg->sessions, iter, session) {
		/* dump session header */
		header.id = session->key.id;
		header.addr = session->key.addr;
		header.difflist_len = r_list_length (session->memlist);
		r_file_dump (diff_file, (ut8 *) &header, sizeof (RSessionHeader), 1);

		/* dump registers */
		r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			RRegArena *arena = session->reg[i]->data;
			r_file_dump (diff_file, (const ut8 *) &arena->size, sizeof (int), 1);
			r_file_dump (diff_file, (const ut8 *) arena->bytes, arena->size, 1);
			// eprintf ("arena[%d] size=%d\n", i, arena->size);
		}
		if (!header.difflist_len) {
			continue;
		}
		// eprintf ("#### Session ####\n");
		// eprintf ("Saved all registers off=0x%"PFMT64x"\n", curp);

		/* Dump all diff entries */
		r_list_foreach (session->memlist, iter2, snapdiff) {
			/* Dump diff header */
			diffentry.pages_len = r_list_length (snapdiff->pages);
			diffentry.base_idx = r_snap_to_idx (dbg, snapdiff->base);
			r_file_dump (diff_file, (const ut8 *) &diffentry, sizeof (RDiffEntry), 1);

			/* Dump page entries */
			r_list_foreach (snapdiff->pages, iter3, page) {
				r_file_dump (diff_file, (const ut8 *) &page->page_off, sizeof (ut32), 1);
				r_file_dump (diff_file, (const ut8 *) page->data, SNAP_PAGE_SIZE, 1);
				r_file_dump (diff_file, (const ut8 *) page->hash, 128, 1);
			}
		}
	}
	eprintf ("Session saved in %s and dump in %s\n", diff_file, base_file);
	free (base_file);
	free (diff_file);
}

R_API void r_debug_session_restore(RDebug *dbg, const char *file) {
	RDebugSnap *base = NULL;
	RDebugSnapDiff *snapdiff;
	RPageData *page;
	RSessionHeader header;
	RDiffEntry diffentry;
	RSnapEntry snapentry;
	ut32 i;

	RReg *reg = dbg->reg;
	const char *path = dbg->snap_path;
	if (!r_file_is_directory (path)) {
		eprintf ("%s is not correct path\n", path);
		return;
	}
	char *base_file = r_str_newf ("%s/%s.dump", path, file);
	char *diff_file = r_str_newf ("%s/%s.session", path, file);

	if (!base_file || !diff_file) {
		free (base_file);
		free (diff_file);
		return;
	}

	FILE *fd = r_sandbox_fopen (base_file, "rb");
	if (!fd) {
		free (base_file);
		free (diff_file);
		return;
	}

	/* Clear current sessions to be replaced */
	r_list_purge (dbg->snaps);

	/* Restore base snapshots */
	while (true) {
		base = r_debug_snap_new ();
		memset (&snapentry, 0, sizeof (RSnapEntry));
		if (fread (&snapentry, sizeof (RSnapEntry), 1, fd) != 1) {
			break;
		}
		base->addr = snapentry.addr;
		base->size = snapentry.size;
		base->addr_end = base->addr + base->size;
		base->page_num = base->size / SNAP_PAGE_SIZE;
		base->timestamp = snapentry.timestamp;
		base->perm = snapentry.perm;
		base->data = calloc (base->size, 1);
		if (!base->data) {
			R_FREE (base);
			break;
		}
		if (fread (base->data, base->size, 1, fd) != 1) {
			free (base->data);
			R_FREE (base);
			break;
		}
		/* restore all hashes */
		base->hashes = R_NEWS0 (ut8 *, base->page_num);
		for (i = 0; i < base->page_num; i++) {
			base->hashes[i] = calloc (1, 128);
			if (fread (base->hashes[i], 128, 1, fd) != 1) {
				break;
			}
		}
		r_list_append (dbg->snaps, base);
	}
	fclose (fd);
	R_FREE (base_file);

	/* Restore trace sessions */
	fd = r_sandbox_fopen (diff_file, "rb");
	R_FREE (diff_file);
	if (!fd) {
		if (base) {
			free (base->data);
			free (base);
		}
		return;
	}

	/* Clear current sessions to be replaced */
	r_list_purge (dbg->sessions);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_purge (reg->regset[i].pool);
	}

	while (true) {
		/* Restore session header */
		if (fread (&header, sizeof (RSessionHeader), 1, fd) != 1) {
			break;
		}
		RDebugSession *session = R_NEW0 (RDebugSession);
		if (!session) {
			break;
		}
		session->memlist = r_list_newf ((RListFree)r_debug_diff_free);
		session->key.id = header.id;
		session->key.addr = header.addr;
		r_list_append (dbg->sessions, session);
		eprintf ("session: %d, 0x%"PFMT64x " diffs: %d\n", header.id, header.addr, header.difflist_len);
		/* Restore registers */
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			/* Resotre RReagArena from raw dump */
			int arena_size;
			if (fread (&arena_size, sizeof (int), 1, fd) != 1) {
				break;
			}
			if (arena_size < 1 || arena_size > 1024*1024) {
				eprintf ("Invalid arena size?\n");
				break;
			}
			ut8 *arena_raw = calloc (arena_size, 1);
			if (!arena_raw) {
				break;
			}
			if (fread (arena_raw, arena_size, 1, fd) != 1) {
				free (arena_raw);
				break;
			}
			RRegArena *arena = R_NEW0 (RRegArena);
			if (!arena) {
				free (arena_raw);
				break;
			}
			arena->bytes = arena_raw;
			arena->size = arena_size;
			/* Push RRegArena to regset.pool */
			r_list_push (reg->regset[i].pool, arena);
			reg->regset[i].arena = arena;
			reg->regset[i].cur = reg->regset[i].pool->tail;
		}
		if (!header.difflist_len) {
			continue;
		}
		/* Restore diff entries */
		for (i = 0; i < header.difflist_len; i++) {
			(void) fread (&diffentry, sizeof (RDiffEntry), 1, fd);
			// eprintf ("diffentry base=%d pages=%d\n", diffentry.base_idx, diffentry.pages_len);
			snapdiff = R_NEW0 (RDebugSnapDiff);
			if (!snapdiff) {
				break;
			}
			/* Restore diff->base */
			base = r_idx_to_snap (dbg, diffentry.base_idx);
			snapdiff->base = base;
			snapdiff->pages = r_list_newf ((RListFree)r_page_data_free);
			snapdiff->last_changes = R_NEWS0 (RPageData *, base->page_num);

			if (r_list_length (base->history)) {
				/* Inherit last changes from previous SnapDiff */
				RDebugSnapDiff *prev_diff = (RDebugSnapDiff *) r_list_tail (base->history)->data;
				memcpy (snapdiff->last_changes, prev_diff->last_changes, sizeof (RPageData *) * base->page_num);
			}
			/* Restore pages */
			ut32 p;
			ut32 clust_page = R_MIN (SNAP_PAGE_SIZE, base->size);
			for (p = 0; p < diffentry.pages_len; p++) {
				page = R_NEW0 (RPageData);
				page->data = calloc (1, clust_page);
				(void) fread (&page->page_off, sizeof (ut32), 1, fd);
				(void) fread (page->data, SNAP_PAGE_SIZE, 1, fd);
				(void) fread (page->hash, 128, 1, fd);
				snapdiff->last_changes[page->page_off] = page;
				r_list_append (snapdiff->pages, page);
			}
			r_list_append (base->history, snapdiff);
			r_list_append (session->memlist, snapdiff);
		}
	}
	/* After restoring all sessions, now sync register */
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 1);

	fclose (fd);
	// #endif
}
