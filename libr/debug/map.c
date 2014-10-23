/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_debug.h>
#include <r_list.h>

R_API void r_debug_map_list(RDebug *dbg, ut64 addr, int rad) {
	int notfirst = R_FALSE;
	RListIter *iter;
	RDebugMap *map;
	switch (rad) {
	case 'j':
		dbg->printf ("[");
		r_list_foreach (dbg->maps, iter, map) {
			if (notfirst) dbg->printf (",");
			dbg->printf ("{\"name\":\"%s\",",map->name);
			dbg->printf ("\"addr\":%"PFMT64u",", map->addr);
			dbg->printf ("\"addr_end\":%"PFMT64u",", map->addr_end);
			dbg->printf ("\"type\":\"%c\",", map->user?'u':'s');
			dbg->printf ("\"perm\":\"%s\"}", r_str_rwx_i (map->perm));
			notfirst = R_TRUE;
		}
		r_list_foreach (dbg->maps_user, iter, map) {
			if (notfirst) dbg->printf (",");
			dbg->printf ("{\"name\":\"%s\",",map->name);
			dbg->printf ("\"addr\":%"PFMT64u",", map->addr);
			dbg->printf ("\"addr_end\":%"PFMT64u",", map->addr_end);
			dbg->printf ("\"type\":\"%c\",", map->user?'u':'s');
			dbg->printf ("\"perm\":\"%s\"}", r_str_rwx_i (map->perm));
			notfirst = R_TRUE;
		}
		dbg->printf ("]\n");
		break;
	case '*':
		r_list_foreach (dbg->maps, iter, map) {
			dbg->printf ("f map.%s.%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				map->name, r_str_rwx_i (map->perm),
				map->addr_end - map->addr, map->addr);
		}
		r_list_foreach (dbg->maps_user, iter, map) {
			dbg->printf ("f map.%s.%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				map->name, r_str_rwx_i (map->perm),
				map->addr_end - map->addr, map->addr);
		}
		break;
	default:
		r_list_foreach (dbg->maps, iter, map) {
			dbg->printf ("sys 0x%08"PFMT64x" %c 0x%08"PFMT64x" %c %s %s\n",
				map->addr, (addr>=map->addr && addr<map->addr_end)?'*':'-',
				map->addr_end, map->user?'u':'s', r_str_rwx_i (map->perm), map->name);
		}
		r_list_foreach (dbg->maps_user, iter, map) {
			dbg->printf ("usr 0x%08"PFMT64x" - 0x%08"PFMT64x" %c %x %s\n",
				map->addr, map->addr_end,
				map->user?'u':'s',
				map->perm, map->name);
		}
		break;
	}
}

R_API RDebugMap *r_debug_map_new (char *name, ut64 addr, ut64 addr_end, int perm, int user) {
	RDebugMap *map;
	if (name == NULL || addr >= addr_end) {
		eprintf ("r_debug_map_new: error assert(%"PFMT64x">=%"PFMT64x")\n", addr, addr_end);
		return NULL;
	}
	map = R_NEW (RDebugMap);
	if (map) {
		map->name = strdup (name);
		map->file = NULL;
		map->addr = addr;
		map->addr_end = addr_end;
		map->size = addr_end-addr;
		map->perm = perm;
		map->user = user;
	}
	return map;
}

R_API int r_debug_map_sync(RDebug *dbg) {
	int ret = R_FALSE;
	if (dbg->h && dbg->h->map_get) {
		RList *newmaps = dbg->h->map_get (dbg);
		if (newmaps) {
			// XXX free all non-user maps // but not unallocate!! only unlink from list
			r_debug_map_list_free (dbg->maps);
			dbg->maps = newmaps;
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API RDebugMap* r_debug_map_alloc(RDebug *dbg, ut64 addr, int size) {
	RDebugMap *map = NULL;
	if (dbg->h && dbg->h->map_alloc) {
		map = dbg->h->map_alloc (dbg, addr, size);
	}
	return map;
}

R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map) {
	int ret = R_FALSE;
	ut64 addr = map->addr;
	if (dbg->h && dbg->h->map_dealloc) {
		if (dbg->h->map_dealloc (dbg, addr, map->size)) {
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API RDebugMap *r_debug_map_get(RDebug *dbg, ut64 addr) {
	RDebugMap *map, *ret = NULL;
	RListIter *iter;
	r_list_foreach (dbg->maps, iter, map) {
		if (addr >= map->addr && addr <= map->addr_end) {
			ret = map;
			break;
		}
	}
	return ret;
}

R_API void r_debug_map_free(RDebugMap *map) {
	//r_list_delete_data (dbg->maps_user, map);
	free (map->name);
	free (map);
}

R_API RList *r_debug_map_list_new() {
	RList *list = r_list_new ();
	list->free = (RListFree)r_debug_map_free;
	return list;
}

/* XXX Use r_list_purge? FIXME: use correct maps->free function */
R_API void r_debug_map_list_free(RList *maps) {
	RListIter *iter;
	RDebugMap *map;
	r_list_foreach (maps, iter, map) {
		r_debug_map_free (map);
	}
	r_list_free (maps);
}
