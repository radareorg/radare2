/* radare - LGPL - Copyright 2017 - rkx1209 */
#include <r_debug.h>

R_API void r_debug_session_free(void *p) {
	free (p);
}

static int r_debug_session_lastid(RDebug *dbg) {
	return r_list_length (dbg->sessions);
}

R_API void r_debug_session_list(RDebug *dbg) {
	const char *comment;
	ut32 count = 0;
	RListIter *iterse, *itersn, *iterpg;
	RDebugSnap *snap;
	RDebugSnapDiff *diff;
	RDebugSession *session;
	RPageData *page;

	r_list_foreach (dbg->sessions, iterse, session) {
		count = 0;
		dbg->cb_printf ("session:%2d\tat:0x%08"PFMT64x "\n", session->key.id, session->key.addr);
		r_list_foreach (session->memlist, itersn, diff) {
			snap = diff->base;
			comment = "";
			if (snap->comment && *snap->comment) {
				comment = snap->comment;
			}
			dbg->cb_printf ("\t- %d 0x%08"PFMT64x " - 0x%08"PFMT64x " size: %d ",
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

R_API bool r_debug_session_add(RDebug *dbg) {
	RDebugSession *session;
	RDebugSnapDiff *diff;
	RListIter *iter;
	RDebugMap *map;
	ut64 addr;
	int i, perms = R_IO_RW;
	session = R_NEW0 (RDebugSession);
	if (!session) {
		return false;
	}

	addr = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
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
	return true;
}

R_API void r_debug_session_set(RDebug *dbg, RDebugSession *session) {
	RDebugSnapDiff *diff;
	RRegArena *arena;
	RListIter *iter, *iterr;
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
	/* Restore all memory values from memory (diff) snapshots */
	r_list_foreach (session->memlist, iter, diff) {
		r_debug_diff_set (dbg, diff);
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

R_API RDebugSession *r_debug_session_get(RDebug *dbg, ut64 addr) {
	RDebugSession *session;
	RListIter *iter;
	r_list_foreach_prev (dbg->sessions, iter, session) {
		if (session->key.addr != addr) {
			/* Sessions are saved along program flow. So key must be compared by "!=" not "<". *
			         ex. Some operations like, jmp, can go back to former address in normal program flow. */
			return session;
		}
	}
	return NULL;
}
