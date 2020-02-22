/* radare2 - LGPL - Copyright 2017-2019 - condret, MaskRay */

#include <r_io.h>
#include <stdlib.h>
#include <sdb.h>
#include "r_binheap.h"
#include "r_util.h"
#include "r_vector.h"

#define END_OF_MAP_IDS UT32_MAX

#define MAP_USE_HALF_CLOSED 0

#define CMP_END_GTE(addr, itv) \
	(((addr) < r_itv_end (*(RInterval *)(itv))) ? -1 : 1)

struct map_event_t {
	RIOMap *map;
	ut64 addr;
	int id; // distinct priority in [0, len(maps))
	bool is_to;
};

// Sort by address, (addr, is_to) precedes (addr, !is_to)
static int _cmp_map_event(const void *a_, const void *b_) {
	struct map_event_t *a = (void *)a_, *b = (void *)b_;
	ut64 addr0 = a->addr - a->is_to, addr1 = b->addr - b->is_to;
	if (addr0 != addr1) {
		return addr0 < addr1? -1: 1;
	}
	if (a->is_to != b->is_to) {
		return !a->is_to? -1: 1;
	}
	if (a->id != b->id) {
		return a->id < b->id? -1: 1;
	}
	return 0;
}

static int _cmp_map_event_by_id(const void *a_, const void *b_) {
	struct map_event_t *a = (void *)a_, *b = (void *)b_;
	return a->id - b->id;
}

// Precondition: from == 0 && to == 0 (full address) or from < to
static bool _map_skyline_push(RPVector *map_skyline, ut64 from, ut64 to, RIOMap *map) {
	RIOMapSkyline *part = R_NEW (RIOMapSkyline), *part1;
	if (!part) {
		return false;
	}
	part->map = map;
	part->itv = (RInterval){ from, to - from };
	if (!from && !to) {
		// Split to two maps
		part1 = R_NEW (RIOMapSkyline);
		if (!part1) {
			free (part);
			return false;
		}
		part1->map = map;
		part1->itv = (RInterval){ UT64_MAX, 1 };
		if (!r_pvector_push (map_skyline, part1)) {
			free (part1);
		}
	}
	if (!r_pvector_push (map_skyline, part)) {
		free (part);
		return false;
	}
	return true;
}

// Store map parts that are not covered by others into io->map_skyline
void io_map_calculate_skyline(RIO *io) {
	SdbListIter *iter;
	RIOMap *map;
	RPVector events;
	RBinHeap heap;
	struct map_event_t *ev;
	bool *deleted = NULL;
	r_pvector_clear (&io->map_skyline);
	r_pvector_clear (&io->map_skyline_shadow);
	r_pvector_init (&events, free);
	if (!r_pvector_reserve (&events, ls_length (io->maps) * 2) ||
			!(deleted = calloc (ls_length (io->maps), 1))) {
		goto out;
	}

	int i = 0;
	// Last map has highest priority (it shadows previous maps),
	// we assign 0 to its event id.
	ls_foreach_prev (io->maps, iter, map) {
		if (!(ev = R_NEW (struct map_event_t))) {
			goto out;
		}
		ev->map = map;
		ev->addr = map->itv.addr;
		ev->is_to = false;
		ev->id = i;
		r_pvector_push (&events, ev);
		if (!(ev = R_NEW (struct map_event_t))) {
			goto out;
		}
		ev->map = map;
		ev->addr = r_itv_end (map->itv);
		ev->is_to = true;
		ev->id = i;
		r_pvector_push (&events, ev);
		i++;
	}
	r_pvector_sort (&events, _cmp_map_event);

	// A min heap whose elements represents active events.
	// The element with the smallest id is at the top.
	r_binheap_init (&heap, _cmp_map_event_by_id);
	ut64 last;
	RIOMap *last_map = NULL;
	for (i = 0; i < r_pvector_len (&events); i++) {
		ev = r_pvector_at (&events, i);
		if (ev->is_to) {
			deleted[ev->id] = true;
		} else {
			r_binheap_push (&heap, ev);
		}
		while (!r_binheap_empty (&heap) && deleted[((struct map_event_t *)r_binheap_top (&heap))->id]) {
			r_binheap_pop (&heap);
		}
		ut64 to = ev->addr;
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
	r_binheap_clear (&heap);

	const RPVector *skyline = &io->map_skyline;
	RPVector *shadow = &io->map_skyline_shadow;
	RInterval *cur_itv = NULL;

	for (i = 0; i < r_pvector_len (skyline); i++) {
		const RIOMapSkyline *part = r_pvector_at (skyline, i);
		if (!part) {
			continue;
		}

		ut64 part_from = part->itv.addr;
		ut64 part_size = part->itv.size;

		if (!cur_itv) {
			cur_itv = r_itv_new (part_from, part_size);
			if (!cur_itv) {
				break;
			}
			continue;
		}

		if (part_from == r_itv_end (*cur_itv)) {
			cur_itv->size += part_size;
		} else {
			if (!r_pvector_push (shadow, cur_itv)) {
				R_FREE (cur_itv);
				break;
			}
			cur_itv = r_itv_new (part_from, part_size);
			if (!cur_itv) {
				break;
			}
		}
	}
	if (cur_itv) {
		if (!r_pvector_push (shadow, cur_itv)) {
			R_FREE (cur_itv);
		}
	}
out:
	r_pvector_clear (&events);
	free (deleted);
}

RIOMap* io_map_new(RIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size, bool do_skyline) {
	if (!size || !io || !io->maps || !io->map_ids) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!map || !io->map_ids || !r_id_pool_grab_id (io->map_ids, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->delta = delta;
	if ((UT64_MAX - size + 1) < addr) {
		/// XXX: this is leaking a map!!!
		io_map_new (io, fd, perm, delta - addr, 0LL, size + addr, do_skyline);
		size = -(st64)addr;
	}
	// RIOMap describes an interval of addresses (map->from; map->to)
	map->itv = (RInterval){ addr, size };
	map->perm = perm;
	map->delta = delta;
	// new map lives on the top, being top the list's tail
	ls_append (io->maps, map);
	if (do_skyline) {
		io_map_calculate_skyline (io);
	}
	return map;
}

R_API RIOMap *r_io_map_new (RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_new (io, fd, perm, delta, addr, size, true);
}

R_API bool r_io_map_remap (RIO *io, ut32 id, ut64 addr) {
	RIOMap *map = r_io_map_resolve (io, id);
	if (map) {
		ut64 size = map->itv.size;
		map->itv.addr = addr;
		if (UT64_MAX - size + 1 < addr) {
			map->itv.size = -addr;
			r_io_map_new (io, map->fd, map->perm, map->delta - addr, 0, size + addr);
			return true;
		}
		io_map_calculate_skyline (io);
		return true;
	}
	return false;
}

R_API bool r_io_map_remap_fd (RIO *io, int fd, ut64 addr) {
	RIOMap *map;
	bool retval = false;
	RList *maps = r_io_map_get_for_fd (io, fd);
	if (maps) {
		map = r_list_get_n (maps, 0);
		if (map) {
			retval = r_io_map_remap (io, map->id, addr);
		}
		r_list_free (maps);
	}
	return retval;
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

RIOMap* io_map_add(RIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size, bool do_skyline) {
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		return io_map_new (io, fd, (perm & desc->perm) | (perm & R_PERM_X),
				delta, addr, size, do_skyline);
	}
	return NULL;
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_add (io, fd, perm, delta, addr, size, true);
}

R_API RIOMap *r_io_map_add_batch(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_add (io, fd, perm, delta, addr, size, false);
}

R_API void r_io_update(RIO *io) {
	io_map_calculate_skyline (io);
}

R_API RIOMap* r_io_map_get_paddr(RIO* io, ut64 paddr) {
	r_return_val_if_fail (io, NULL);
	RIOMap* map;
	SdbListIter* iter;
	ls_foreach_prev (io->maps, iter, map) {
		if (map->delta <= paddr && paddr <= map->delta + map->itv.size - 1) {
			return map;
		}
	}
	return NULL;
}

// gets first map where addr fits in
R_API RIOMap* r_io_map_get(RIO* io, ut64 addr) {
	r_return_val_if_fail (io, NULL);
	RIOMap* map;
	SdbListIter* iter;
	ls_foreach_prev (io->maps, iter, map) {
		if (r_itv_contain (map->itv, addr)) {
			return map;
		}
	}
	return NULL;
}

R_API bool r_io_map_is_mapped(RIO* io, ut64 addr) {
	r_return_val_if_fail (io, false);
	const RPVector *shadow = &io->map_skyline_shadow;
	size_t i, len = r_pvector_len (shadow);
	r_pvector_lower_bound (shadow, addr, i, CMP_END_GTE);
	if (i == len) {
		return false;
	}
	const RInterval *itv = r_pvector_at (shadow, i);
	if (itv->addr <= addr) {
		return true;
	}
	return false;
}

R_API void r_io_map_reset(RIO* io) {
	r_io_map_fini (io);
	r_io_map_init (io);
	io_map_calculate_skyline (io);
}

R_API bool r_io_map_del(RIO* io, ut32 id) {
	r_return_val_if_fail (io, false);
	RIOMap* map;
	SdbListIter* iter;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {
			ls_delete (io->maps, iter);
			r_id_pool_kick_id (io->map_ids, id);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	r_return_val_if_fail (io, false);
	SdbListIter* iter, * ator;
	RIOMap* map;
	bool ret = false;
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
		io_map_calculate_skyline (io);
	}
	return ret;
}

//brings map with specified id to the tail of of the list
//return a boolean denoting whether is was possible to priorized
R_API bool r_io_map_priorize(RIO* io, ut32 id) {
	r_return_val_if_fail (io, false);
	RIOMap *map;
	SdbListIter *iter;
	ls_foreach (io->maps, iter, map) {
		// search for iter with the correct map
		if (map->id == id) {
			ls_split_iter (io->maps, iter);
			ls_append (io->maps, map);
			io_map_calculate_skyline (io);
			free (iter);
			return true;
		}
	}
	return false;
}

R_API bool r_io_map_depriorize(RIO* io, ut32 id) {
	r_return_val_if_fail (io, false);
	RIOMap *map;
	SdbListIter *iter;
	ls_foreach (io->maps, iter, map) {
		// search for iter with the correct map
		if (map->id == id) {
			ls_split_iter (io->maps, iter);
			ls_prepend (io->maps, map);
			io_map_calculate_skyline (io);
			free (iter);
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
	//temporary set to avoid free the map and to speed up ls_delete a bit
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
	io_map_calculate_skyline (io);
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
		io_map_calculate_skyline (io);
	}
}

R_API void r_io_map_fini(RIO* io) {
	r_return_if_fail (io);
	ls_free (io->maps);
	io->maps = NULL;
	r_id_pool_free (io->map_ids);
	io->map_ids = NULL;
	r_pvector_clear (&io->map_skyline);
	r_pvector_clear (&io->map_skyline_shadow);
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

// TODO: very similar to r_io_map_next_address, decide which one to use
R_API ut64 r_io_map_next_available(RIO* io, ut64 addr, ut64 size, ut64 load_align) {
	RIOMap* map;
	SdbListIter* iter;
	ut64 next_addr = addr,
	end_addr = next_addr + size;
	ls_foreach (io->maps, iter, map) {
		ut64 to = r_itv_end (map->itv);
		next_addr = R_MAX (next_addr, to + (load_align - (to % load_align)) % load_align);
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files. infinite loop ahead?
		if ((map->itv.addr <= next_addr && next_addr < to) || r_itv_contain (map->itv, end_addr)) {
			next_addr = to + (load_align - (to % load_align)) % load_align;
			return r_io_map_next_available (io, next_addr, size, load_align);
		}
		break;
	}
	return next_addr;
}

// TODO: very similar to r_io_map_next_available. decide which one to use
R_API ut64 r_io_map_next_address(RIO* io, ut64 addr) {
	RIOMap* map;
	SdbListIter* iter;
	ut64 lowest = UT64_MAX;

	ls_foreach (io->maps, iter, map) {
		ut64 from = r_itv_begin (map->itv);
		if (from > addr && addr < lowest) {
			lowest = from;
		}
		ut64 to = r_itv_end (map->itv);
		if (to > addr && to < lowest) {
			lowest = to;
		}
	}
	return lowest;
}

R_API RList* r_io_map_get_for_fd(RIO* io, int fd) {
	RList* map_list = r_list_newf (NULL);
	SdbListIter* iter;
	RIOMap* map;
	if (!map_list) {
		return NULL;
	}
	ls_foreach (io->maps, iter, map) {
		if (map && map->fd == fd) {
			r_list_append (map_list, map);
		}
	}
	return map_list;
}

R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	RIOMap *map;
	if (!newsize || !(map = r_io_map_resolve (io, id))) {
		return false;
	}
	ut64 addr = map->itv.addr;
	if (UT64_MAX - newsize + 1 < addr) {
		map->itv.size = -addr;
		r_io_map_new (io, map->fd, map->perm, map->delta - addr, 0, newsize + addr);
		return true;
	}
	map->itv.size = newsize;
	io_map_calculate_skyline (io);
	return true;
}

// find a location that can hold enough bytes without overlapping
// XXX this function is buggy and doesnt works as expected, but i need it for a PoC for now
R_API ut64 r_io_map_location(RIO *io, ut64 size) {
	ut64 base = (io->bits == 64)? 0x60000000000LL: 0x60000000;
	while (r_io_map_get (io, base)) {
		base += 0x200000;
	}
	return base;
}
