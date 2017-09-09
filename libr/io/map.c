/* radare2 - LGPL - Copyright 2017 - condret, MaskRay */

#include <r_io.h>
#include <stdlib.h>
#include <sdb.h>
#include "r_binheap.h"
#include "r_util.h"
#include "r_vector.h"

#define END_OF_MAP_IDS  0xffffffff

#define MAP_USE_HALF_CLOSED 0

struct map_event_t {
	RIOMap *map;
	ut64 addr;
	int id; // distinct priority in [0, len(maps))
	bool is_to;
};

// Sort by address, (addr, !is_to) precedes (addr, is_to)
static int _cmp_map_event(const void *a_, const void *b_) {
	struct map_event_t *a = (void *)a_, *b = (void *)b_;
	if (a->addr != b->addr) {
		return a->addr < b->addr ? -1 : 1;
	}
	return a->is_to - b->is_to; // TODO swap if half-closed
}

static int _cmp_map_event_by_id(const void *a_, const void *b_) {
	struct map_event_t *a = (void *)a_, *b = (void *)b_;
	return a->id - b->id;
}

static bool _map_skyline_push(RVector *map_skyline, ut64 from, ut64 to, RIOMap *map) {
	RIOMapSkyline *part = R_NEW (RIOMapSkyline);
	if (!part) {
		return false;
	}
	part->map = map;
	part->from = from;
	part->to = to - 1; // TODO half-closed
	return r_vector_push (map_skyline, part);
}

// Store map parts that are not covered by others into io->map_skyline
R_API void r_io_map_calculate_skyline(RIO *io) {
#define PUSH
	SdbListIter *iter;
	RIOMap *map;
	RVector events = {0};
	RBinHeap heap;
	struct map_event_t *ev;
	bool *deleted = NULL;
	r_vector_clear (&io->map_skyline, free);
	if (!r_vector_reserve (&events, ls_length (io->maps) * 2) ||
			!(deleted = calloc (ls_length (io->maps), 1))) {
		goto out;
	}

	int i = 0;
	ls_foreach (io->maps, iter, map) {
		if (!(ev = R_NEW (struct map_event_t))) {
			goto out;
		}
		ev->map = map;
		ev->addr = map->from;
		ev->is_to = false;
		ev->id = i;
		r_vector_push (&events, ev);
		if (!(ev = R_NEW (struct map_event_t))) {
			goto out;
		}
		ev->map = map;
		ev->addr = map->to;
		ev->is_to = true;
		ev->id = i;
		r_vector_push (&events, ev);
		i++;
	}
	r_vector_sort (&events, _cmp_map_event);

	r_binheap_init (&heap, _cmp_map_event_by_id);
	ut64 last;
	RIOMap *last_map = NULL;
	for (i = 0; i < events.len; i++) {
		ev = events.a[i];
		if (ev->is_to) {
			deleted[ev->id] = true;
		} else {
			r_binheap_push (&heap, ev);
		}
		while (!r_binheap_empty (&heap) && deleted[((struct map_event_t *)r_binheap_top (&heap))->id]) {
			r_binheap_pop (&heap);
		}
		ut64 to = ev->addr + ev->is_to; // TODO half-closed
		map = r_binheap_empty (&heap) ? NULL : ((struct map_event_t *)r_binheap_top (&heap))->map;
		if (!i) {
			last = to;
			last_map = map;
		} else if (last != to || (!to && ev->is_to)) {
			if (last_map != map) {
				if (last_map && !_map_skyline_push (&io->map_skyline, last, to, last_map)) {
					break;
				}
				last = to;
				last_map = map;
			}
			if (!to && ev->is_to) {
				if (map) {
					(void)_map_skyline_push (&io->map_skyline, last, to, map);
				}
				// This is a to == 2**64 event. There are no more skyline parts.
				break;
			}
		} else if (map && (!last_map || map->id > last_map->id)) {
			last_map = map;
		}
	}

	r_binheap_clear (&heap, NULL);
out:
	r_vector_clear (&events, free);
	free (deleted);
}

R_API RIOMap* r_io_map_new(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline) {
	if (!size || !io || !io->maps || !io->map_ids) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!map || !io->map_ids || !r_id_pool_grab_id (io->map_ids, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->from = addr;
	map->delta = delta;
	if ((UT64_MAX - size + 1) < addr) {
		r_io_map_new (io, fd, flags, UT64_MAX - addr + 1 + delta, 0LL, size - (UT64_MAX - addr) - 1, do_skyline);
		size = UT64_MAX - addr + 1;
	}
	// RIOMap describes an interval of addresses (map->from; map->to)
	map->to = addr + size - 1;
	map->flags = flags;
	map->delta = delta;
	// new map lives on the top, being top the list's tail
	ls_prepend (io->maps, map);
	// TODO When maps are added in batch (sections), do not recalculate each time
	//_calculate_skyline (io);
	return map;
}

R_API bool r_io_map_remap (RIO *io, ut32 id, ut64 addr) {
	RIOMap *map;
	ut64 size;
	if (!(map = r_io_map_resolve (io, id))) {
		return false;
	}
	size = map->to - map->from + 1;
	map->from = addr;
	if ((UT64_MAX - size + 1) < addr) {
		r_io_map_new (io, map->fd, map->flags, UT64_MAX - addr + 1 + map->delta, 0LL, size - (UT64_MAX - addr) - 1, true);
		size = UT64_MAX - addr + 1;
		map->to = UT64_MAX;
		return true;
	}
	map->to = addr + size - 1;
	r_io_map_calculate_skyline (io);
	return true;
}

static void _map_free(void* p) {
	RIOMap* map = (RIOMap*) p;
	if (map) {
		free (map->name);
		free (map);
	}
}

R_API void r_io_map_init(RIO* io) {
	if (io && !io->maps) {
		io->maps = ls_newf ((SdbListFree)_map_free);
		if (io->map_ids) {
			r_id_pool_free (io->map_ids);
		}
		io->map_ids = r_id_pool_new (1, END_OF_MAP_IDS);
	}
}

// check if a map with exact the same properties exists
R_API bool r_io_map_exists(RIO* io, RIOMap* map) {
	SdbListIter* iter;
	RIOMap* m;
	if (!io || !io->maps || !map) {
		return false;
	}
	ls_foreach (io->maps, iter, m) {
		if (!memcmp (m, map, sizeof (RIOMap))) {
			return true;
		}
	}
	return false;
}

// check if a map with specified id exists
R_API bool r_io_map_exists_for_id(RIO* io, ut32 id) {
	return r_io_map_resolve (io, id) != NULL;
}

R_API RIOMap* r_io_map_resolve(RIO* io, ut32 id) {
	SdbListIter* iter;
	RIOMap* map;
	if (!io || !io->maps || !id) {
		return NULL;
	}
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {
			return map;
		}
	}
	return NULL;
}

R_API RIOMap* r_io_map_add(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline) {
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		SdbListIter* iter;
		RIOMap* map;
		ls_foreach (io->maps, iter, map) {
			if (map->fd == fd && map->from == addr &&
			    map->to == addr + size - 1 && map->delta == delta) {
				return NULL;
			}
		}
		//a map cannot have higher permissions than the desc belonging to it
		return r_io_map_new (io, fd, (flags & desc->flags) | (flags & R_IO_EXEC),
				delta, addr, size, do_skyline);
	}
	return NULL;
}

R_API RIOMap* r_io_map_get_paddr(RIO* io, ut64 paddr) {
	RIOMap* map;
	SdbListIter* iter;
	if (!io) {
		return NULL;
	}
	ls_foreach_prev (io->maps, iter, map) {
		ut64 size = map->to - map->from + 1;
		if ((map->delta <= paddr) && (map->delta + size > paddr)) {
			return map;
		}
	}
	return NULL;
}

// gets first map where addr fits in
R_API RIOMap* r_io_map_get(RIO* io, ut64 addr) {
	RIOMap* map;
	SdbListIter* iter;
	if (!io) {
		return NULL;
	}
	ls_foreach_prev (io->maps, iter, map) {
		if ((map->from <= addr) && (map->to >= addr)) {
			return map;
		}
	}
	return NULL;
}

R_API bool r_io_map_del(RIO* io, ut32 id) {
	SdbListIter* iter;
	RIOMap* map;
	if (!io) {
		return false;
	}
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {
			ls_delete (io->maps, iter);
			r_id_pool_kick_id (io->map_ids, id);
			r_io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	SdbListIter* iter, * ator;
	RIOMap* map;
	bool ret = false;
	if (!io) {
		return ret;
	}
	ls_foreach_safe (io->maps, iter, ator, map) {
		if (!map) {
			ls_delete (io->maps, iter);
		} else if (map->fd == fd) {
			r_id_pool_kick_id (io->map_ids, map->id);
			//delete iter and map
			ls_delete (io->maps, iter);
			ret = true;
		}
	}
	if (ret) {
		r_io_map_calculate_skyline (io);
	}
	return ret;
}

//brings map with specified id to the tail of of the list
//return a boolean denoting whether is was possible to priorized
R_API bool r_io_map_priorize(RIO* io, ut32 id) {
	SdbListIter* iter;
	RIOMap* map;
	if (!io) {
		return false;
	}
	ls_foreach (io->maps, iter, map) {
		//search for iter with the correct map
		if (map->id == id) {
			ls_split_iter (io->maps, iter);
			ls_append (io->maps, map);
			r_io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

R_API bool r_io_map_priorize_for_fd(RIO* io, int fd) {
	SdbListIter* iter, * ator;
	RIOMap *map;
	SdbList* list;
	if (!io || !io->maps) {
		return false;
	}
	if (!(list = ls_new ())) {
		return false;
	}
	//we need a clean list for this, or this becomes a segfault-field
	r_io_map_cleanup (io);
	//tempory set to avoid free the map and to speed up ls_delete a bit
	io->maps->free = NULL;
	ls_foreach_safe (io->maps, iter, ator, map) {
		if (map->fd == fd) {
			ls_prepend (list, map);
			ls_delete (io->maps, iter);
		}
	}
	ls_join (io->maps, list);
	ls_free (list);
	io->maps->free = _map_free;
	r_io_map_calculate_skyline (io);
	return true;
}


//may fix some inconsistencies in io->maps
R_API void r_io_map_cleanup(RIO* io) {
	SdbListIter* iter, * ator;
	RIOMap* map;
	if (!io || !io->maps) {
		return;
	}
	//remove all maps if no descs exist
	if (!io->files) {
		r_io_map_fini (io);
		r_io_map_init (io);
		return;
	}
	bool del = false;
	ls_foreach_safe (io->maps, iter, ator, map) {
		//remove iter if the map is a null-ptr, this may fix some segfaults
		if (!map) {
			ls_delete (io->maps, iter);
			del = true;
		} else if (!r_io_desc_get (io, map->fd)) {
			//delete map and iter if no desc exists for map->fd in io->files
			r_id_pool_kick_id (io->map_ids, map->id);
			ls_delete (io->maps, iter);
			del = true;
		}
	}
	if (del) {
		r_io_map_calculate_skyline (io);
	}
}

R_API void r_io_map_fini(RIO* io) {
	if (!io) {
		return;
	}
	ls_free (io->maps);
	io->maps = NULL;
	r_id_pool_free (io->map_ids);
	io->map_ids = NULL;
	r_vector_clear (&io->map_skyline, free);
}

R_API void r_io_map_set_name(RIOMap* map, const char* name) {
	if (!map || !name) {
		return;
	}
	free (map->name);
	map->name = strdup (name);
}

R_API void r_io_map_del_name(RIOMap* map) {
	if (map) {
		R_FREE (map->name);
	}
}

R_API bool r_io_map_is_in_range(RIOMap* map, ut64 from, ut64 to) { //rename pls
	if (!map || (to < from)) {
		return false;
	}
	if (R_BETWEEN (map->from, from, map->to)) {
		return true;
	}
	if (R_BETWEEN (map->from, to, map->to)) {
		return true;
	}
	if (map->from > from && to > map->to) {
		return true;
	}
	return false;
}

//TODO: Kill it with fire
R_API RIOMap* r_io_map_add_next_available(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, ut64 load_align) {
	RIOMap* map;
	SdbListIter* iter;
	ut64 next_addr = addr,
	end_addr = next_addr + size;
	ls_foreach (io->maps, iter, map) {
		next_addr = R_MAX (next_addr, map->to + (load_align - (map->to % load_align)) % load_align);
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files.

		if (map->fd == fd && ((map->from <= next_addr && next_addr < map->to) ||
		(map->from <= end_addr && end_addr < map->to))) {
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			next_addr = map->to + (load_align - (map->to % load_align)) % load_align;
			return r_io_map_add_next_available (io, fd, flags, delta, next_addr, size, load_align);
		} else {
			break;
		}
	}
	return r_io_map_new (io, fd, flags, delta, next_addr, size, true);
}
