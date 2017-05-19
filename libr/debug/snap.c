/* radare - LGPL - Copyright 2015 - pancake */

#include <r_debug.h>
#include <r_hash.h>

R_API RDebugSnap* r_debug_snap_new() {
	RDebugSnap *snap = R_NEW0 (RDebugSnap);
	if (!snap) {
		return NULL;
	}
	snap->history = r_list_newf (r_debug_diff_free);
	snap->crcs = r_list_new ();
	return snap;
}

R_API void r_debug_snap_free (void *p) {
	RDebugSnap *snap = (RDebugSnap*)p;
	r_list_free (snap->crcs);
	r_list_free (snap->history);
	free (snap->data);
	free (snap->comment);
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
	if (mode == 'j')
		dbg->cb_printf ("[");
	r_list_foreach (dbg->snaps, iter, snap) {
		comment = "";
		comma = (iter->n)? ",":"";
		if (idx != -1) {
			if (idx != count) {
				continue;
			}
		}
		if (snap->comment && *snap->comment)
			comment = snap->comment;
		switch (mode) {
		case 'j':
			dbg->cb_printf ("{\"count\":%d,\"addr\":%"PFMT64d",\"size\":%d,\"comment\":\"%s\"}%s",
				count, snap->addr, snap->size, comment, comma);
			break;
		case '*':
			dbg->cb_printf ("dms 0x%08"PFMT64x"\n", snap->addr);
			break;
		default:
			dbg->cb_printf ("%d 0x%08"PFMT64x" - 0x%08"PFMT64x" size: %d  --  %s\n",
				count, snap->addr, snap->addr_end, snap->size, comment);
		}
		count++;
	}
	if (mode == 'j')
		dbg->cb_printf ("]\n");
}

R_API RDebugSnap* r_debug_snap_get (RDebug *dbg, ut64 addr) {
	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (dbg->snaps, iter, snap) {
		if (R_BETWEEN (snap->addr, addr, snap->addr_end - 1)) {
			return snap;
		}
	}
	return NULL;
}

R_API int r_debug_snap_set (RDebug *dbg, RDebugSnap *snap) {
	RListIter *iter;
	RDebugMap *map;
	eprintf ("Writing %d bytes to 0x%08"PFMT64x"...\n", snap->size, snap->addr);
	r_list_foreach (dbg->maps, iter, map) {
		if (snap->addr <= map->addr && map->addr_end <= snap->addr_end) {
			dbg->iob.write_at (dbg->iob.io, map->addr, snap->data, map->addr_end - map->addr);
		}
	}
	return 1;
}

R_API int r_debug_snap_set_idx (RDebug *dbg, int idx) {
	RDebugSnap *snap;
	RListIter *iter;
	ut32 count = 0;
	if (!dbg || idx < 0)
		return 0;
	r_list_foreach (dbg->snaps, iter, snap) {
		if (count == idx) {
			r_debug_snap_set (dbg, snap);
			break;
		}
		count++;
	}
	return 1;
}

static int r_debug_snap_map (RDebug *dbg, RDebugMap *map) {
	if (!dbg || !map || map->size < 1) {
		eprintf ("Invalid map size\n");
		return 0;
	}
	RDebugSnap *snap = r_debug_snap_new ();
	if (!snap) {
		return 0;
	}
	snap->timestamp = sdb_now ();
	snap->addr = map->addr;
	snap->addr_end = map->addr_end;
	snap->size = map->size;
	snap->data = malloc (map->size);
	if (!snap->data) {
		free (snap);
		return 0;
	}
	eprintf ("Reading %d bytes from 0x%08"PFMT64x"...\n", snap->size, snap->addr);
	dbg->iob.read_at (dbg->iob.io, snap->addr, snap->data, snap->size);

	r_list_append (dbg->snaps, snap);
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
		eprintf ("Cannot find map at 0x%08"PFMT64x"\n", addr);
		return 0;
	}
	return r_debug_snap_map (dbg, map);
}

R_API int r_debug_snap_comment (RDebug *dbg, int idx, const char *msg) {
	RDebugSnap *snap;
	RListIter *iter;
	ut32 count = 0;
	if (!dbg || idx<0 || !msg || !*msg)
		return 0;
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

R_API void r_debug_diff_free (void *p) {
	free (p);
}
