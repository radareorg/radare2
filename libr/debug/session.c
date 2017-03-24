/* radare - LGPL - Copyright 2017 - rkx1209 */
#include <r_debug.h>

R_API void r_debug_session_free (void *p) {
	RDebugSession *session = (RDebugSession*)p;
	free (session);
}

static int r_debug_session_lastid (RDebug *dbg) {
  return r_list_length (dbg->sessions);
}

R_API int r_debug_session_list (RDebug *dbg) {
  const char *comment;
  ut32 count = 0;
	RListIter *iterse, *itersn;
	RDebugSnap *snap;
  RDebugSession *session;
	r_list_foreach (dbg->sessions, iterse, session) {
    count = 0;
    dbg->cb_printf ("session:%2d\tat:0x%08"PFMT64x"\n", session->key.id, session->key.addr);
	  r_list_foreach (session->memlist, itersn, snap) {
		  comment = "";
		  if (snap->comment && *snap->comment)
			  comment = snap->comment;
		  dbg->cb_printf ("%d 0x%08"PFMT64x" - 0x%08"PFMT64x" size: %d crc: %x  --  %s\n",
		                  count, snap->addr, snap->addr_end, snap->size, snap->crc, comment);
		  count++;
    }
	}
}

R_API int r_debug_session_add (RDebug *dbg) {
	RDebugSession *session;
  RDebugSnap *snap;
  RListIter *iter, *start, *iterr;
  ut64 addr;
  int i;
	session = R_NEW0 (RDebugSession);
  if (!session) return 0;

  addr = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
  session->key = (RDebugKey) { addr, r_debug_session_lastid (dbg) };

  /* save current registers */
  r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
  for (i = 0; i < R_REG_TYPE_LAST; i++) {
    session->reg[i] = r_list_tail (dbg->reg->regset[i].pool);
  }
  r_reg_arena_push (dbg->reg);

  /* save memory snapshots */
  session->memlist = r_list_newf (r_debug_snap_free);
  start = r_list_tail (dbg->snaps);
  r_debug_snap_all (dbg, R_IO_RW);
  if (!start) {
    start = r_list_head (dbg->snaps);
  } else {
    start = start->n;
  }
  //XXX
  for (iter = start; iter && (snap = iter->data); iter = iter->n) {
    r_list_append (session->memlist, snap);
  }

  r_list_append (dbg->sessions, session);
  return 1;
}

R_API int r_debug_session_set (RDebug *dbg, RDebugSession *session) {
  RDebugSnap *snap;
  RRegArena *arena;
  RListIter *iter, *iterr;
  int i;
  /* Restore all regsiter values from the stack area pointed by session */
  r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
  for (i = 0; i < R_REG_TYPE_LAST; i++) {
    iterr = session->reg[i];
    arena = iterr->data;
    memcpy (dbg->reg->regset[i].arena->bytes, arena->bytes, arena->size);
  }
  r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 1);

  /* Restore all memory values from memory snapshots*/
  r_list_foreach (session->memlist, iter, snap) {
    r_debug_snap_set (dbg, snap);
  }
  return 1;
}

R_API int r_debug_session_set_idx (RDebug *dbg, int idx) {
  RDebugSession *session;
  RListIter *iter;
  ut32 count = 0;

  if (!dbg || idx < 0)
    return 0;

  r_list_foreach (dbg->sessions, iter, session) {
    if (count == idx) {
      r_debug_session_set (dbg, session);
      return 1;
    }
    count++;
  }
  return 0;
}

R_API RDebugSession* r_debug_session_get (RDebug *dbg, ut64 addr) {
  RDebugSession *session;
  RListIter *iter;
  r_list_foreach_prev (dbg->sessions, iter, session) {
    if (session->key.addr != addr) return session;
  }
  return NULL;
}
