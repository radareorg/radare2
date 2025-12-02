/* radare2 - LGPL - Copyright 2017-2024 - condret, MaskRay */

#include <r_io.h>

#define END_OF_MAP_IDS UT32_MAX
R_IPI bool io_bank_has_map(RIO *io, const ut32 bankid, const ut32 mapid);

static RIOMap *io_map_new(RIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	const ut64 fd_size = r_io_fd_size (io, fd);
	if ((!size) || (fd_size <= delta)) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!r_id_storage_add (&io->maps, map, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->delta = delta;
	map->ts = io->mts++;
	// RIOMap describes an interval of addresses
	// r_io_map_from (map) -> r_io_map_to (map)
	map->itv = (RInterval){ addr, R_MIN (size, fd_size - delta) };
	map->perm = perm;
	return map;
}

R_API bool r_io_map_remap(RIO *io, ut32 id, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (io, false);
	RIOMap *map = r_io_map_get (io, id);
	if (!map) {
		return false;
	}
	const ut64 ofrom = r_io_map_from (map);
	const ut64 oto = r_io_map_to (map);
	ut64 size = r_io_map_size (map);
	if (map->overlay) {
		if (R_UNLIKELY (UT64_MAX - size + 1 < addr)) {
			R_LOG_ERROR ("Mapsplit for overlay maps is not possible");
			return false;
		}
	}
	r_io_map_set_begin (map, addr);
	if (R_UNLIKELY (UT64_MAX - size + 1 < addr)) {
		st64 saddr = (st64)addr;
		const ut64 osize = r_io_map_size (map);
		r_io_map_set_size (map, -saddr);
		RIOMap *newmap = r_io_map_add (io, map->fd, map->perm, map->delta - addr, 0, size + addr);
		if (newmap) {
			if (!io_bank_has_map (io, io->bank, id)) {
				r_io_bank_del_map (io, io->bank, newmap->id);
			}
			ut32 bankid;
			r_id_storage_get_lowest (&io->banks, &bankid);
			do {
				if (bankid != io->bank && io_bank_has_map (io, bankid, id)) {
					// TODO: use threads here
					r_io_bank_map_add_top (io, bankid, newmap->id);
				}
			} while (r_id_storage_get_next (&io->banks, &bankid));
		} else {
			// restore previous location and size if creation of newmap failed
			r_io_map_set_begin (map, ofrom);
			r_io_map_set_size (map, osize);
			return false;
		}
	}
	ut32 bankid;
	r_id_storage_get_lowest (&io->banks, &bankid);
	do {
		// TODO: use threads here
		r_io_bank_update_map_boundaries (io, bankid, id, ofrom, oto);
	} while (r_id_storage_get_next (&io->banks, &bankid));
	return true;
}

R_API bool r_io_map_remap_fd(RIO *io, int fd, ut64 addr) {
	RIOMap *map;
	bool retval = false;
	RList *maps = r_io_map_get_by_fd (io, fd);
	if (maps) {
		map = r_list_get_n (maps, 0);	//this looks wrong
		if (map) {
			retval = r_io_map_remap (io, map->id, addr);
		}
		r_list_free (maps);
	}
	return retval;
}

static bool _map_free_cb(void *user, void *data, ut32 id) {
	RIOMap *map = (RIOMap *)data;
	if (map) {
		r_crbtree_free (map->overlay);
		free (map->name);
		free (map);
	}
	return true;
}

R_API void r_io_map_init(RIO* io) {
	R_RETURN_IF_FAIL (io);
	r_id_storage_foreach (&io->maps, _map_free_cb, NULL);
	r_id_storage_fini (&io->maps);
	r_id_storage_init (&io->maps, 1, END_OF_MAP_IDS);
}

// check if a map with exact the same properties exists
R_API bool r_io_map_exists(RIO *io, RIOMap *map) {
	R_RETURN_VAL_IF_FAIL (io && map, false);
	RIOMap *_map = r_io_map_get (io, map->id);
	if (!_map) {
		return false;
	}
	return !memcmp (_map, map, sizeof (RIOMap));
}

// check if a map with specified id exists
R_API bool r_io_map_exists_for_id(RIO *io, ut32 id) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return r_io_map_get (io, id);
}

R_API RIOMap* r_io_map_get(RIO *io, ut32 id) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return r_id_storage_get (&io->maps, id);
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	if (!size) {
		return NULL;
	}
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		perm &= (desc->perm | R_PERM_X);
		RIOMap *map[2] = {NULL, NULL};
		if (R_UNLIKELY ((UT64_MAX - size + 1) < addr)) {
			const ut64 new_size = UT64_MAX - addr + 1;
			map[0] = io_map_new (io, fd, perm, delta + new_size, 0LL, size - new_size);
			if (!map[0]) {
				return NULL;
			}
			if (!r_io_bank_map_add_top (io, io->bank, map[0]->id)) {
				r_id_storage_delete (&io->maps, map[0]->id);
				free (map[0]);
				return NULL;
			}
			size = new_size;
		}
		map[1] = io_map_new (io, fd, perm, delta, addr, size);
		if (!map[1]) {
			if (map[0]) {
				r_id_storage_delete (&io->maps, map[0]->id);
				free (map[0]);
			}
			free (map[1]);
			return NULL;
		}
		if (!r_io_bank_map_add_top (io, io->bank, map[1]->id)) {
			if (map[0]) {
				r_id_storage_delete (&io->maps, map[0]->id);
				free (map[0]);
			}
			r_id_storage_delete (&io->maps, map[1]->id);
			free (map[1]);
			return NULL;
		}
		return map[1];
	}
	return NULL;
}

R_API RIOMap *r_io_map_add_bottom(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	if (!size) {
		return NULL;
	}
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		perm &= desc->perm | R_PERM_X;
		RIOMap *map[2] = {NULL, NULL};
		if (R_UNLIKELY ((UT64_MAX - size + 1) < addr)) {
			const ut64 new_size = UT64_MAX - addr + 1;
			map[0] = io_map_new (io, fd, perm, delta + new_size, 0LL, size - new_size);
			if (!map[0]) {
				return NULL;
			}
			if (!r_io_bank_map_add_bottom (io, io->bank, map[0]->id)) {
				r_id_storage_delete (&io->maps, map[0]->id);
				free (map[0]);
				return NULL;
			}
			size = new_size;
		}
		map[1] = io_map_new (io, fd, perm, delta, addr, size);
		if (!map[1]) {
			if (map[0]) {
				r_id_storage_delete (&io->maps, map[0]->id);
				free (map[0]);
			}
			free (map[1]);
			return NULL;
		}
		if (!r_io_bank_map_add_bottom (io, io->bank, map[1]->id)) {
			if (map[0]) {
				r_id_storage_delete (&io->maps, map[0]->id);
				free (map[0]);
			}
			r_id_storage_delete (&io->maps, map[1]->id);
			free (map[1]);
			return NULL;
		}
		return map[1];
	}
	return NULL;
}

// Confusing function name
R_API RIOMap *r_io_map_get_paddr(RIO* io, ut64 paddr) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	RIOBank *bank = r_io_bank_get (io, io->bank);
	if (bank) {
		RListIter *iter;
		RIOMapRef *mapref;
		r_list_foreach_prev (bank->maprefs, iter, mapref) {
			RIOMap *map = r_io_map_get_by_ref (io, mapref);
			if (map && map->delta <= paddr && paddr < map->delta + r_io_map_size (map)) {
				return map;
			}
		}
	}
	return NULL;
}

// gets first map where addr fits in
R_API RIOMap *r_io_map_get_at(RIO* io, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	return r_io_bank_get_map_at (io, io->bank, addr);
}

R_API bool r_io_map_is_mapped(RIO* io, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return (bool)r_io_map_get_at (io, addr);
}

R_API void r_io_map_reset(RIO* io) {
	r_io_map_fini (io);
	r_io_map_init (io);
}

R_API void r_io_map_del(RIO *io, ut32 id) {
	R_RETURN_IF_FAIL (io);
	RIOMap *map = (RIOMap *)r_id_storage_get (&io->maps, id);
	if (!map) {
		return;
	}
	ut32 bankid = 0;
	if (!r_id_storage_get_lowest (&io->banks, &bankid)) {
		R_LOG_ERROR ("Cannot get the lowest bankid");
		return;
	}
	do {
		// TODO: use threads for every bank, except the current bank (io->bank)
		r_io_bank_del_map (io, bankid, id);
	} while (r_id_storage_get_next (&io->banks, &bankid));
	r_id_storage_delete (&io->maps, id);
	_map_free_cb (NULL, map, id);
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, false);
	ut32 map_id;
	if (!r_id_storage_get_lowest (&io->maps, &map_id)) {
		return false;
	}

	bool ret = false;
	bool cont;
	do {
		ut32 next = map_id;	// is this actually needed?
		cont = r_id_storage_get_next (&io->maps, &next);
		RIOMap *map = r_io_map_get (io, map_id);
		if (map->fd == fd) {
			ret = true;
			r_io_map_del (io, map_id);
		}
		map_id = next;
	} while (cont);
	return ret;
}

//brings map with specified id to the tail of of the list
//return a boolean denoting whether is was possible to priorized
R_API bool r_io_map_priorize(RIO* io, ut32 id) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return r_io_bank_map_priorize (io, io->bank, id);
}

R_API bool r_io_map_depriorize(RIO* io, ut32 id) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return r_io_bank_map_depriorize (io, io->bank, id);
}

R_API bool r_io_map_priorize_for_fd(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, false);
	RList *map_list = r_io_map_get_by_fd (io, fd);
	if (!map_list) {
		return false;
	}
	RListIter *iter;
	RIOMap *map;
	r_list_foreach (map_list, iter, map) {
		r_io_map_priorize (io, map->id);
	}
	r_list_free (map_list);
	return true;
}

//may fix some inconsistencies in io->maps
R_API void r_io_map_cleanup(RIO* io) {
	R_RETURN_IF_FAIL (io);
	//remove all maps if no descs exist
	if (!io->files.data) {
		r_io_map_fini (io);
		r_io_map_init (io);
		return;
	}
	// TODO: implement RIOBank mapref consistency cleanup here @condret
}

static bool _clear_banks_cb(void *user, void *data, ut32 id) {
	r_io_bank_clear ((RIOBank *)data);
	return true;
}

R_API void r_io_map_fini(RIO* io) {
	R_RETURN_IF_FAIL (io);
	r_id_storage_foreach (&io->banks, _clear_banks_cb, NULL);
	r_id_storage_foreach (&io->maps, _map_free_cb, NULL);
	r_id_storage_fini (&io->maps);
	io->maps = (const RIDStorage){0};
}

R_API void r_io_map_set_name(RIOMap* map, const char* name) {
	R_RETURN_IF_FAIL (map && name);
	free (map->name);
	map->name = strdup (name);
}

R_API void r_io_map_del_name(RIOMap* map) {
	R_RETURN_IF_FAIL (map);
	R_FREE (map->name);
}

R_API bool r_io_map_locate(RIO *io, ut64 *addr, const ut64 size, ut64 load_align) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return r_io_bank_locate (io, io->bank, addr, size, load_align);
}

R_API RList* r_io_map_get_by_fd(RIO* io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	RList* map_list = r_list_newf (NULL);
	if (!map_list) {
		return NULL;
	}
	RIOBank *bank = r_io_bank_get (io, io->bank);
	if (!bank) {
		r_list_free (map_list);
		return NULL;
	}
	RListIter *iter;
	RIOMapRef *mapref;
	r_list_foreach_prev (bank->maprefs, iter, mapref) {
		RIOMap *map = (RIOMap *)r_id_storage_get (&io->maps, mapref->id);
		if (map->fd == fd) {
			r_list_append (map_list, map);
		}
	}
	return map_list;
}

R_IPI bool io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	R_RETURN_VAL_IF_FAIL (io, false);
	RIOMap *map;
	if (!newsize || !(map = r_io_map_get (io, id))) {
		return false;
	}
	ut64 addr = r_io_map_begin (map);
	const ut64 oto = r_io_map_to (map);
	if (UT64_MAX - newsize + 1 < addr) {
		st64 saddr = (st64)addr;
		const ut64 osize = r_io_map_size (map);
		r_io_map_set_size (map, -saddr);
		RIOMap *newmap = r_io_map_add (io, map->fd, map->perm, map->delta - addr, 0, newsize + addr);
		if (newmap) {
			if (!io_bank_has_map (io, io->bank, id)) {
				r_io_bank_del_map (io, io->bank, newmap->id);
			} else {
				r_io_bank_update_map_boundaries (io, io->bank, id, r_io_map_from (map), oto);
			}
			ut32 bankid;
			r_id_storage_get_lowest (&io->banks, &bankid);
			do {
				if (bankid != io->bank && io_bank_has_map (io, bankid, id)) {
					// TODO: use threads here
					r_io_bank_update_map_boundaries (io, io->bank, id, r_io_map_from (map), oto);
					r_io_bank_map_add_top (io, bankid, newmap->id);
				}
			} while (r_id_storage_get_next (&io->banks, &bankid));
		} else {
			// restore previous size if creating newmap failed
			r_io_map_set_size (map, osize);
			return false;
		}
		return true;
	}
	r_io_map_set_size (map, newsize);
	ut32 bankid;
	r_id_storage_get_lowest (&io->banks, &bankid);
	do {
		if (io_bank_has_map (io, bankid, id)) {
			// TODO: use threads here
			r_io_bank_update_map_boundaries (io, bankid, id, r_io_map_from (map), oto);
		}
	} while (r_id_storage_get_next (&io->banks, &bankid));
	return true;
}

R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	R_RETURN_VAL_IF_FAIL (io, false);
	RIOMap *map;
	if (!newsize || !(map = r_io_map_get (io, id))) {
		return false;
	}
	if (r_io_map_size (map) == newsize) {
		return true;
	}
	if (!(map->tie_flags & R_IO_MAP_TIE_FLG_FORTH)) {
		return io_map_resize (io, id, newsize);
	}
	const ut64 fdsize = r_io_fd_size (io, map->fd);
	const double ratio = ((double)newsize) / ((double)r_io_map_size (map));
	ut64 newfdsize = (ut64)((double)fdsize * ratio);
	if ((newsize > r_io_map_size (map)) && (newfdsize < fdsize)) {
		newfdsize = UT64_MAX;
	}
	r_io_fd_resize (io, map->fd, newfdsize);
	return io_map_resize (io, id, newsize);
}

R_API RIOMap *r_io_map_get_by_ref(RIO *io, RIOMapRef *ref) {
	R_RETURN_VAL_IF_FAIL (io && ref, NULL);
	RIOMap *map = r_io_map_get (io, ref->id);
	// trigger cleanup if ts don't match?
	return (map && map->ts == ref->ts) ? map : NULL;
}

typedef struct map_overlay_chunk_t {
	// itv is relative to the map vaddr
	// this is to keep maps with overlay moveable in the va space
	RInterval itv;
	ut8 *buf;
} MapOverlayChunk;

static int _overlay_chunk_find(void *incoming, void *in, void *user) {
	RInterval *itv = (RInterval *)incoming;
	MapOverlayChunk *chunk = (MapOverlayChunk *)in;
	if (r_itv_overlap (itv[0], chunk->itv)) {
		return 0;
	}
	if (r_itv_begin (itv[0]) < r_itv_begin (chunk->itv)) {
		return -1;
	}
	return 1;
}

R_API void r_io_map_read_from_overlay(RIOMap *map, ut64 addr, ut8 *buf, int len) {
	R_RETURN_IF_FAIL (map && buf);
	if (!map->overlay || len < 1 || addr > r_io_map_to (map)) {
		return;
	}
	RInterval x = {addr, len};
	RInterval search_itv = r_itv_intersect (map->itv, x);
	search_itv.addr -= map->itv.addr;	// to keep things remappable
	RRBNode *node = r_crbtree_find_node (map->overlay, &search_itv, _overlay_chunk_find, NULL);
	if (!node) {
		return;
	}
	MapOverlayChunk *chunk = NULL;
	RRBNode *prev = r_rbnode_prev (node);
	while (prev) {
		chunk = (MapOverlayChunk *)prev->data;
		if (!r_itv_overlap (chunk->itv, search_itv)) {
			break;
		}
		node = prev;
		prev = r_rbnode_prev (prev);
	}
	chunk = (MapOverlayChunk *)node->data;
	do {
		addr = R_MAX (r_itv_begin (search_itv), r_itv_begin (chunk->itv));
		ut8 *dst = &buf[addr - r_itv_begin (search_itv)];
		const ut8 *src = &chunk->buf[addr - r_itv_begin (chunk->itv)];
		const size_t read_len = (size_t)(R_MIN (r_itv_end (search_itv), r_itv_end (chunk->itv)) - addr);
		memcpy (dst, src, read_len);
		node = r_rbnode_next (node);
		chunk = node? (MapOverlayChunk *)node->data: NULL;
	} while (chunk && r_itv_overlap (chunk->itv, search_itv));
}

static void _overlay_chunk_free(void *data) {
	if (!data) {
		return;
	}
	MapOverlayChunk *chunk = (MapOverlayChunk *)data;
	free (chunk->buf);
	free (chunk);
}

static int _overlay_chunk_insert(void *incoming, void *in, void *user) {
	MapOverlayChunk *incoming_chunk = (MapOverlayChunk *)incoming;
	MapOverlayChunk *in_chunk = (MapOverlayChunk *)in;
	if (r_itv_begin (incoming_chunk->itv) < r_itv_begin (in_chunk->itv)) {
		return -1;
	}
	if (r_itv_begin (incoming_chunk->itv) > r_itv_begin (in_chunk->itv)) {
		return 1;
	}
	return 0;
}

R_API bool r_io_map_write_to_overlay(RIOMap *map, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (map && buf, false);
	RInterval x = {addr, len};
	RInterval search_itv = r_itv_intersect (map->itv, x);
	if (!r_itv_size (search_itv)) {
		return true;	// is this correct?
	}
	if (!map->overlay) {
		if (!(map->overlay = r_crbtree_new (_overlay_chunk_free))) {
			return false;
		}
	}
	search_itv.addr -= map->itv.addr;
	RRBNode *node = r_crbtree_find_node (map->overlay, &search_itv, _overlay_chunk_find, NULL);
	if (!node) {
		MapOverlayChunk *chunk = R_NEW0 (MapOverlayChunk);
		chunk->buf = R_NEWS (ut8, r_itv_size (search_itv));
		chunk->itv = search_itv;
		if (!chunk->buf || !r_crbtree_insert (map->overlay, chunk, _overlay_chunk_insert, NULL)) {
			free (chunk->buf);
			free (chunk);
			return false;
		}
		memcpy (chunk->buf, buf, r_itv_size (search_itv));
		return true;
	}
	MapOverlayChunk *chunk = NULL;
	RRBNode *prev = r_rbnode_prev (node);
	while (prev) {
		chunk = (MapOverlayChunk *)prev->data;
		if (!r_itv_overlap (chunk->itv, search_itv)) {
			break;
		}
		node = prev;
		prev = r_rbnode_prev (prev);
	}
	chunk = (MapOverlayChunk *)node->data;
	if (r_itv_include (chunk->itv, search_itv)) {
		ut8 *dst = &chunk->buf[r_itv_begin (search_itv) - r_itv_begin (chunk->itv)];
		memcpy (dst, buf, r_itv_size (search_itv));
		return true;
	}
	if (r_itv_begin (chunk->itv) < r_itv_begin (search_itv)) {
		chunk->itv.size = r_itv_begin (search_itv) - r_itv_begin (chunk->itv);
		// realloc can only fail here on bad implementations, because the new size is smaller than the old size
		ut8 *ptr = realloc (chunk->buf, r_itv_size (chunk->itv));
		if (R_UNLIKELY (!ptr)) {
			return false;
		}
		chunk->buf = ptr;
		node = r_rbnode_next (node);
	}
	if (node) {
		chunk = (MapOverlayChunk *)node->data;
		while (chunk && r_itv_include (search_itv, chunk->itv)) {
			node = r_rbnode_next (node);
			r_crbtree_delete (map->overlay, &chunk->itv, _overlay_chunk_find, NULL);
			chunk = node? (MapOverlayChunk *)node->data: NULL;
		}
		if (chunk && r_itv_end (search_itv) >= r_itv_begin (chunk->itv)) {
			ut8 *ptr = realloc (chunk->buf,
				(r_itv_end (chunk->itv) - r_itv_begin (search_itv)) * sizeof (ut8));
			if (!ptr) {
				return false;
			}
			chunk->buf = ptr;
			memmove (&chunk->buf[r_itv_size (search_itv)],
				&chunk->buf[r_itv_end (search_itv) - r_itv_begin (chunk->itv)],
				r_itv_end (chunk->itv) - r_itv_end (search_itv));
			memcpy (chunk->buf, buf, r_itv_size (search_itv));
			chunk->itv.size = r_itv_end (chunk->itv) - r_itv_begin (search_itv);
			chunk->itv.addr = search_itv.addr;
			return true;
		}
	}
	chunk = R_NEW0 (MapOverlayChunk);
	chunk->buf = R_NEWS (ut8, r_itv_size (search_itv));
	if (!chunk->buf) {
		free (chunk);
		return false;
	}
	chunk->itv = search_itv;
	memcpy (chunk->buf, buf, r_itv_size (search_itv));
	r_crbtree_insert (map->overlay, chunk, _overlay_chunk_insert, NULL);
	return true;
}

R_IPI bool io_map_get_overlay_intersects(RIOMap *map, RQueue *q, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (map && q, false);
	if (!map->overlay) {
		return true;
	}
	RInterval search_itv = {addr - map->itv.addr, len};
	RRBNode *node = r_crbtree_find_node (map->overlay, &search_itv, _overlay_chunk_find, NULL);
	if (!node) {
		return true;
	}
	MapOverlayChunk *chunk = NULL;
	RRBNode *prev = r_rbnode_prev (node);
	while (prev) {
		chunk = (MapOverlayChunk *)prev->data;
		if (!r_itv_overlap (chunk->itv, search_itv)) {
			break;
		}
		node = prev;
		prev = r_rbnode_prev (prev);
	}
	chunk = (MapOverlayChunk *)node->data;
	do {
		if (!r_queue_enqueue (q, &chunk->itv)) {
			// allocation in r_queue failed
			while (!r_queue_is_empty (q)) {
				r_queue_dequeue (q);
			}
			return false;
		}
		node = r_rbnode_next (node);
		chunk = node ? (MapOverlayChunk *)node->data : NULL;
	} while (chunk && r_itv_overlap (search_itv, chunk->itv));
	return true;
}

R_API void r_io_map_drain_overlay(RIOMap *map) {
	R_RETURN_IF_FAIL (map);
	if (!map->overlay || map->overlay->size < 2) {
		return;
	}
	RQueue *q = r_queue_new (map->overlay->size - 1);
	if (!q) {
		return;
	}
	RRBNode *start_n = r_crbtree_first_node (map->overlay);
	RRBNode *cur_n = start_n;
	RRBNode *next_n = r_rbnode_next (cur_n);
	while (next_n) {
		MapOverlayChunk *cur = (MapOverlayChunk *)cur_n->data;
		MapOverlayChunk *next = (MapOverlayChunk *)next_n->data;
		if (r_itv_end (cur->itv) == r_itv_begin (next->itv)) {
			r_queue_enqueue (q, cur);	// cannot, because q was initialized with enough capacity
			cur_n = next_n;
		} else {
			if (!r_queue_is_empty (q)) {
				MapOverlayChunk *start = (MapOverlayChunk *)start_n->data;
				const ut64 new_size = r_itv_end (cur->itv) - r_itv_begin (start->itv);
				ut8 *buf = realloc (start->buf, new_size * sizeof (ut8));
				if (buf) {
					start->buf = buf;
					memmove (&buf[r_itv_begin (cur->itv) - r_itv_begin (start->itv)],
						cur->buf, r_itv_size (cur->itv));
					r_crbtree_delete (map->overlay, cur, _overlay_chunk_insert, NULL);
					r_queue_dequeue (q);	// first elem is always start
					while (!r_queue_is_empty (q)) {
						cur = (MapOverlayChunk *)r_queue_dequeue (q);
						memcpy (&buf[r_itv_begin (cur->itv) - r_itv_begin (start->itv)],
							cur->buf, r_itv_size (cur->itv));
						r_crbtree_delete (map->overlay, cur, _overlay_chunk_insert, NULL);
					}
					start->itv.size = new_size;
				} else {
					while (!r_queue_is_empty (q)) {
						r_queue_dequeue (q);
					}
				}
				start_n = cur_n = next_n;
			}
		}
		next_n = r_rbnode_next (next_n);
	}
	if (!r_queue_is_empty (q)) {
		MapOverlayChunk *cur = (MapOverlayChunk *)cur_n->data;
		MapOverlayChunk *start = (MapOverlayChunk *)start_n->data;
		const ut64 new_size = r_itv_end (cur->itv) - r_itv_begin (start->itv);
		ut8 *buf = realloc (start->buf, new_size * sizeof (ut8));
		if (buf) {
			start->buf = buf;
			memmove (&buf[r_itv_begin (cur->itv) - r_itv_begin (start->itv)],
				cur->buf, r_itv_size (cur->itv));
			r_crbtree_delete (map->overlay, cur, _overlay_chunk_insert, NULL);
			r_queue_dequeue (q);	//first elem is always start
			while (!r_queue_is_empty (q)) {
				cur = (MapOverlayChunk *)r_queue_dequeue (q);
				memcpy (&buf[r_itv_begin (cur->itv) - r_itv_begin (start->itv)],
					cur->buf, r_itv_size (cur->itv));
				r_crbtree_delete (map->overlay, cur, _overlay_chunk_insert, NULL);
			}
			start->itv.size = new_size;
		} else {
			while (!r_queue_is_empty (q)) {
				r_queue_dequeue (q);
			}
		}
	}
	r_queue_free (q);
}

R_API void r_io_map_overlay_foreach(RIOMap *map, RIOMapOverlayForeach cb, void *user) {
	R_RETURN_IF_FAIL (map && cb);
	if (!map->overlay || !map->overlay->size) {
		return;
	}
	RRBNode *node = r_crbtree_first_node (map->overlay);
	if (!node) {
		return;
	}
	do {
		MapOverlayChunk *moc = node->data;
		RInterval itv = {
			moc->itv.addr + map->itv.addr,
			moc->itv.size
		};
		cb (itv, moc->buf, user);
	} while ((node = r_rbnode_next (node)), node);
}

static const char* metatypename[R_IO_MAP_META_TYPE_LAST] = {
	[R_IO_MAP_META_TYPE_NONE] = "",
	[R_IO_MAP_META_TYPE_HEAP] = "heap",
	[R_IO_MAP_META_TYPE_STACK] = "stack",
	[R_IO_MAP_META_TYPE_MMAP] = "mmap",
	[R_IO_MAP_META_TYPE_MMIO] = "mmio",
	[R_IO_MAP_META_TYPE_DMA] = "dma",
	[R_IO_MAP_META_TYPE_JIT] = "jit",
	[R_IO_MAP_META_TYPE_BSS] = "bss",
	[R_IO_MAP_META_TYPE_SHARED] = "shared",
	[R_IO_MAP_META_TYPE_KERNEL] = "kernel",
	[R_IO_MAP_META_TYPE_GUARD] = "guard",
	[R_IO_MAP_META_TYPE_NULL] = "null",
	[R_IO_MAP_META_TYPE_GPU] = "gpu",
	[R_IO_MAP_META_TYPE_TLS] = "tls",
	[R_IO_MAP_META_TYPE_BUFFER] = "buffer",
	[R_IO_MAP_META_TYPE_COW] = "cow",
	[R_IO_MAP_META_TYPE_PAGETABLES] = "pagetables"
};

static const char *metaflagname[16] = {
	"paged",
	"private",
	"persistent",
	"aslr",
	"swap",
	"dep",
	"enclave",
	"compressed",
	"encrypted",
	"large",
	0
};

R_API bool r_io_map_setattr_fromstring(RIOMap *map, const char *s) {
	int i, maptype;
	for (maptype = 0; maptype < R_IO_MAP_META_TYPE_LAST; maptype++) {
		if (strstr (s, metatypename[maptype])) {
			ut32 mapflag = 0;
			for (i = 0; i < R_IO_MAP_META_FLAG_LAST; i++) {
				if (strstr (s, metaflagname[i])) {
					mapflag |= (1 << i);
				}
			}
			return r_io_map_setattr (map, maptype, mapflag);
		}
	}
	R_LOG_DEBUG ("invalid map type string");
	return false;
}

R_API bool r_io_map_setattr(RIOMap *map, ut32 type, ut32 flags) {
	if (type >= R_IO_MAP_META_TYPE_LAST) {
		R_LOG_DEBUG ("invalid map type");
		return false;
	}
	if (flags >= R_IO_MAP_META_FLAG_LAST) {
		R_LOG_DEBUG ("invalid map flags");
		return false;
	}
	map->meta = type | (flags << 16);
	return true;
}

R_API char *r_io_map_getattr(RIOMap *map) {
	ut32 maptype = map->meta & 0xffff;
	ut32 mapflag = (map->meta > 16) & 0xffff;
	if (maptype >= R_IO_MAP_META_TYPE_LAST) {
		return false;
	}
	if (mapflag >= R_IO_MAP_META_FLAG_LAST) {
		return false;
	}
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, metatypename[maptype]);
	int i = 0;
	for (i = 0; i < 16; i++) {
		if (mapflag & i) {
			r_strbuf_append (sb, "+");
			r_strbuf_append (sb, metaflagname[i]);
		}
	}
	return r_strbuf_drain (sb);
}
