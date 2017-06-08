/* radare - LGPL - Copyright 2017 - rkx1209 */
#include <r_debug.h>

R_API void r_debug_session_free(void *p) {
	free (p);
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
		dbg->cb_printf ("session:%2d   at:0x%08"PFMT64x "\n", session->key.id, session->key.addr);
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
	int i, perms = R_IO_RW;

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

	/* save current registers */
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		session->reg[i] = r_list_tail (dbg->reg->regset[i].pool);
	}
	r_reg_arena_push (dbg->reg);

	/* save memory snapshots */
	session->memlist = r_list_newf (r_debug_diff_free);

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

static void r_debug_session_set_registers(RDebug *dbg, RDebugSession *session) {
	RRegArena *arena;
	RListIter *iterr;
	int i;
	/* Restore all regsiter values from the stack area pointed by session */
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

R_API void r_debug_session_set(RDebug *dbg, RDebugSession *session) {
	RListIter *iter;
	RDebugSnapDiff *diff;
	r_debug_session_set_registers (dbg, session);
	/* Restore all memory values from memory (diff) snapshots */
	r_list_foreach (session->memlist, iter, diff) {
		r_debug_diff_set (dbg, diff);
	}
}

R_API void r_debug_session_set_base(RDebug *dbg, RDebugSession *before) {
	RListIter *iter;
	RDebugSnap *snap;
	r_debug_session_set_registers (dbg, before);
	/* Restore all memory values from base memory snapshots */
	r_list_foreach (dbg->snaps, iter, snap) {
		r_debug_diff_set_base (dbg, snap);
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
	RListIter *prev;
	if (!tail) {
		return NULL;
	}
	prev = tail->p;
	if (!prev) {
		return NULL;
	}
	session = (RDebugSession *)prev->data;
	return session;
}
