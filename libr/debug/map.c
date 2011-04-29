/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_list.h>

R_API void r_debug_map_list(struct r_debug_t *dbg, ut64 addr) {
	RListIter *iter = r_list_iterator (dbg->maps);
	while (r_list_iter_next (iter)) {
		RDebugMap *map = r_list_iter_get (iter);
		eprintf ("sys 0x%08"PFMT64x" %c 0x%08"PFMT64x" %c %s %s\n",
			map->addr, (addr>=map->addr && addr<=map->addr_end)?'*':'-',
			map->addr_end, map->user?'u':'s', r_str_rwx_i (map->perm), map->name);
	}
	iter = r_list_iterator (dbg->maps_user);
	while (r_list_iter_next (iter)) {
		RDebugMap *map = r_list_iter_get (iter);
		eprintf ("usr 0x%08"PFMT64x" - 0x%08"PFMT64x" %c %x %s\n",
			map->addr, map->addr_end,
			map->user?'u':'s',
			map->perm, map->name);
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

R_API int r_debug_map_alloc(RDebug *dbg, RDebugMap *map) {
	int ret = R_FALSE;
	if (dbg->h && dbg->h->map_alloc) {
		if (dbg->h->map_alloc (dbg, map)) {
			ret = R_TRUE;
			r_list_append (dbg->maps_user, map);
		}
	}
	return ret;
}

R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map) {
	int ret = R_FALSE;
	ut64 addr = map->addr;
	if (dbg->h && dbg->h->map_dealloc) 
		if (dbg->h->map_dealloc (dbg, addr)) {
			ret = R_TRUE;
			r_list_unlink (dbg->maps_user, map);
		}
	//r_debug_map_free (map);
	return ret;
}

R_API RDebugMap *r_debug_map_get(RDebug *dbg, ut64 addr) {
	RDebugMap *ret = NULL;
	RListIter *iter = r_list_iterator (dbg->maps);
	while (r_list_iter_next (iter)) {
		RDebugMap *map = r_list_iter_get (iter);
		if (addr >= map->addr && addr <= map->addr_end) {
			ret = map;
			break;
		}
	}
	return ret;
}

R_API void r_debug_map_free(RDebugMap *map) {
	//r_list_unlink (dbg->maps_user, map);
	free (map->name);
	free (map);
}

R_API RList *r_debug_map_list_new() {
	RList *list = r_list_new ();
	list->free = (RListFree)r_debug_map_free;
	return list;
}

/* XXX Use r_list_destroy? */
R_API void r_debug_map_list_free(RList *maps) {
	RListIter *iter = r_list_iterator (maps);
	while (r_list_iter_next (iter)) {
		RDebugMap *map = r_list_iter_get (iter);
		r_debug_map_free (map);
	}
	r_list_free (maps);
}
