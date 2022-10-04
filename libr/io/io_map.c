/* radare2 - LGPL - Copyright 2017-2022 - condret, MaskRay */

#include <r_io.h>
#include <stdlib.h>
#include <sdb.h>
#include <r_util.h>

#define END_OF_MAP_IDS UT32_MAX
R_IPI bool io_bank_has_map(RIO *io, const ut32 bankid, const ut32 mapid);

static RIOMap *io_map_new(RIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	r_return_val_if_fail (io && io->maps, NULL);
	if (!size) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!map || !r_id_storage_add (io->maps, map, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->delta = delta;
	map->ts = io->mts++;
	// RIOMap describes an interval of addresses
	// r_io_map_from (map) -> r_io_map_to (map)
	map->itv = (RInterval){ addr, size };
	map->perm = perm;
	map->delta = delta;
	return map;
}

R_API bool r_io_map_remap(RIO *io, ut32 id, ut64 addr) {
	RIOMap *map = r_io_map_get (io, id);
	r_return_val_if_fail (io && map, false);
	const ut64 ofrom = r_io_map_from (map);
	const ut64 oto = r_io_map_to (map);
	ut64 size = r_io_map_size (map);
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
			r_id_storage_get_lowest (io->banks, &bankid);
			do {
				if (bankid != io->bank && io_bank_has_map (io, bankid, id)) {
					// TODO: use threads here
					r_io_bank_map_add_top (io, bankid, newmap->id);
				}
			} while (r_id_storage_get_next (io->banks, &bankid));
		} else {
			// restore previous location and size if creation of newmap failed
			r_io_map_set_begin (map, ofrom);
			r_io_map_set_size (map, osize);
			return false;
		}
	}
	ut32 bankid;
	r_id_storage_get_lowest (io->banks, &bankid);
	do {
		// TODO: use threads here
		r_io_bank_update_map_boundaries (io, bankid, id, ofrom, oto);
	} while (r_id_storage_get_next (io->banks, &bankid));
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
		if ((map->perm & R_PERM_RELOC) && map->reloc_map && map->reloc_map->free) {
			map->reloc_map->free (map->reloc_map->data);
			// don't free map->reloc_map here, could be static
		}
		free (map->name);
		free (map);
	}
	return true;
}

R_API void r_io_map_init(RIO* io) {
	r_return_if_fail (io);
	if (io->maps) {
		r_id_storage_foreach (io->maps, _map_free_cb, NULL);
		r_id_storage_free (io->maps);
	}
	io->maps = r_id_storage_new (1, END_OF_MAP_IDS);
}

// check if a map with exact the same properties exists
R_API bool r_io_map_exists(RIO *io, RIOMap *map) {
	r_return_val_if_fail (io && map, false);
	RIOMap *_map = r_io_map_get (io, map->id);
	if (!_map) {
		return false;
	}
	return !memcmp (_map, map, sizeof (RIOMap));
}

// check if a map with specified id exists
R_API bool r_io_map_exists_for_id(RIO *io, ut32 id) {
	r_return_val_if_fail (io && io->maps, false);
	return r_io_map_get (io, id);
}

R_API RIOMap* r_io_map_get(RIO *io, ut32 id) {
	r_return_val_if_fail (io, false);
	return r_id_storage_get (io->maps, id);
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	r_return_val_if_fail (io, NULL);
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
			if (!r_io_bank_map_add_top (io, io->bank, map[0]->id)) {
				r_id_storage_delete (io->maps, map[0]->id);
				free (map[0]);
				return NULL;
			}
			size = new_size;
		}
		map[1] = io_map_new (io, fd, perm, delta, addr, size);
		if (!map[1]) {
			if (map[0]) {
				r_id_storage_delete (io->maps, map[0]->id);
				free (map[0]);
			}
			free (map[1]);
			return NULL;
		}
		if (!r_io_bank_map_add_top (io, io->bank, map[1]->id)) {
			if (map[0]) {
				r_id_storage_delete (io->maps, map[0]->id);
				free (map[0]);
			}
			r_id_storage_delete (io->maps, map[1]->id);
			free (map[1]);
			return NULL;
		}
		return map[1];
	}
	return NULL;
}

R_API RIOMap *r_io_reloc_map_add(RIO *io, int fd, int perm, RIORelocMap *rm, ut64 addr, ut64 size) {
	r_return_val_if_fail (io && rm, NULL);
	if (!size) {
		return NULL;
	}
	//cannot split reloc maps
	if ((UT64_MAX - size + 1) < addr) {
		return NULL;
	}
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (!desc) {
		return NULL;
	}
	perm &= desc->perm | R_PERM_X;
	perm |= R_PERM_RELOC;
	RIOMap *map = io_map_new (io, fd, perm, 0, addr, size);
	if (map) {
		if (!r_io_bank_map_add_top (io, io->bank, map->id)) {
			r_id_storage_delete (io->maps, map->id);
			free (map);
			if (rm->free) {
				rm->free (rm->data);
			}
			return NULL;
		}
		map->reloc_map = rm;
	}
	return map;
}

R_API RIOMap *r_io_map_add_bottom(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	r_return_val_if_fail (io, NULL);
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
				r_id_storage_delete (io->maps, map[0]->id);
				free (map[0]);
				return NULL;
			}
			size = new_size;
		}
		map[1] = io_map_new (io, fd, perm, delta, addr, size);
		if (!map[1]) {
			if (map[0]) {
				r_id_storage_delete (io->maps, map[0]->id);
				free (map[0]);
			}
			free (map[1]);
			return NULL;
		}
		if (!r_io_bank_map_add_bottom (io, io->bank, map[1]->id)) {
			if (map[0]) {
				r_id_storage_delete (io->maps, map[0]->id);
				free (map[0]);
			}
			r_id_storage_delete (io->maps, map[1]->id);
			free (map[1]);
			return NULL;
		}
		return map[1];
	}
	return NULL;
}

R_API RIOMap *r_io_map_get_paddr(RIO* io, ut64 paddr) {
	r_return_val_if_fail (io, NULL);
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
	r_return_val_if_fail (io, NULL);
	return r_io_bank_get_map_at (io, io->bank, addr);
}

R_API bool r_io_map_is_mapped(RIO* io, ut64 addr) {
	r_return_val_if_fail (io, false);
	return (bool)r_io_map_get_at (io, addr);
}

R_API void r_io_map_reset(RIO* io) {
	r_io_map_fini (io);
	r_io_map_init (io);
}

R_API void r_io_map_del(RIO *io, ut32 id) {
	r_return_if_fail (io && io->maps);
	RIOMap *map = (RIOMap *)r_id_storage_get (io->maps, id);
	if (!map) {
		return;
	}
	ut32 bankid;
	r_return_if_fail (r_id_storage_get_lowest (io->banks, &bankid));
	do {
		// TODO: use threads for every bank, except the current bank (io->bank)
		r_io_bank_del_map (io, bankid, id);
	} while (r_id_storage_get_next (io->banks, &bankid));
	r_id_storage_delete (io->maps, id);
	_map_free_cb (NULL, map, id);
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	r_return_val_if_fail (io && io->maps, false);
	ut32 map_id;
	if (!r_id_storage_get_lowest (io->maps, &map_id)) {
		return false;
	}

	bool ret = false;
	bool cont;
	do {
		ut32 next = map_id;	// is this actually needed?
		cont = r_id_storage_get_next (io->maps, &next);
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
	r_return_val_if_fail (io, false);
	return r_io_bank_map_priorize (io, io->bank, id);
}

R_API bool r_io_map_depriorize(RIO* io, ut32 id) {
	r_return_val_if_fail (io, false);
	return r_io_bank_map_depriorize (io, io->bank, id);
}

R_API bool r_io_map_priorize_for_fd(RIO *io, int fd) {
	r_return_val_if_fail (io, false);
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
	r_return_if_fail (io);
	//remove all maps if no descs exist
	if (!io->files) {
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
	r_return_if_fail (io);
	r_id_storage_foreach (io->banks, _clear_banks_cb, NULL);
	r_id_storage_foreach (io->maps, _map_free_cb, NULL);
	r_id_storage_free (io->maps);
	io->maps = NULL;
}

R_API void r_io_map_set_name(RIOMap* map, const char* name) {
	r_return_if_fail (map && name);
	free (map->name);
	map->name = strdup (name);
}

R_API void r_io_map_del_name(RIOMap* map) {
	r_return_if_fail (map);
	R_FREE (map->name);
}

R_API bool r_io_map_locate(RIO *io, ut64 *addr, const ut64 size, ut64 load_align) {
	r_return_val_if_fail (io, false);
	if (load_align == 0) {
		load_align = 1;
	}
	return r_io_bank_locate (io, io->bank, addr, size, load_align);
}

R_API RList* r_io_map_get_by_fd(RIO* io, int fd) {
	r_return_val_if_fail (io, NULL);
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
		RIOMap *map = (RIOMap *)r_id_storage_get (io->maps, mapref->id);
		if (map->fd == fd) {
			r_list_append (map_list, map);
		}
	}
	return map_list;
}

R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	r_return_val_if_fail (io, false);
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
			r_id_storage_get_lowest (io->banks, &bankid);
			do {
				if (bankid != io->bank && io_bank_has_map (io, bankid, id)) {
					// TODO: use threads here
					r_io_bank_update_map_boundaries (io, io->bank, id, r_io_map_from (map), oto);
					r_io_bank_map_add_top (io, bankid, newmap->id);
				}
			} while (r_id_storage_get_next (io->banks, &bankid));
		} else {
			// restore previous size if creating newmap failed
			r_io_map_set_size (map, osize);
			return false;
		}
		return true;
	}
	r_io_map_set_size (map, newsize);
	ut32 bankid;
	r_id_storage_get_lowest (io->banks, &bankid);
	do {
		if (io_bank_has_map (io, bankid, id)) {
			// TODO: use threads here
			r_io_bank_update_map_boundaries (io, bankid, id, r_io_map_from (map), oto);
		}
	} while (r_id_storage_get_next (io->banks, &bankid));
	return true;
}

R_API RIOMap *r_io_map_get_by_ref(RIO *io, RIOMapRef *ref) {
	r_return_val_if_fail (io && ref, NULL);
	RIOMap *map = r_io_map_get (io, ref->id);
	// trigger cleanup if ts don't match?
	return (map && map->ts == ref->ts) ? map : NULL;
}
