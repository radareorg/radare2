/* radare2 - LGPL - Copyright 2017-2018 - condret, MaskRay */

#include <r_io.h>
#include <stdlib.h>
#include <sdb.h>
#include "r_binheap.h"
#include "r_util.h"
#include "r_vector.h"

#define END_OF_MAP_IDS UT32_MAX

#define MAP_USE_HALF_CLOSED 0

R_API RIOMap* r_io_map_new(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size) {
	ut32 od;
	if (!size || !io || !io->maps) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!map) {
		return NULL;
	}
	map->fd = fd;
	map->delta = delta;
	if ((UT64_MAX - size + 1) < addr) {
		/// XXX: this is leaking a map!!!
		//this is ok
		r_io_map_new (io, fd, flags, delta - addr, 0LL, size + addr);
		size = -(st64)addr;
	}
	// RIOMap describes an interval of addresses (map->from; map->to)
	map->itv = (RInterval){ addr, size };
	map->flags = flags;
	map->delta = delta;
	// new map lives on the top, being top the list's tail
	if (!r_oids_add (io->maps, map, &map->id, &od)) {
		R_FREE (map);
	} else {
		r_io_submap_repress (io, map);
	}
	return map;
}

R_API bool r_io_map_remap (RIO *io, ut32 id, ut64 addr) {
	RIOMap *map = r_io_map_resolve (io, id);
	if (map) {
		r_io_submap_cut_out (io, map->itv.addr,
				map->itv.addr + map->itv.size - 1);
		ut64 size = map->itv.size;
		map->itv.addr = addr;
		if (UT64_MAX - size + 1 < addr) {
			map->itv.size = -addr;
			r_io_submap_cut_out (io, map->itv.addr,
					map->itv.addr + map->itv.size - 1);
			r_io_map_new (io, map->fd, map->flags, map->delta - addr, 0, size + addr);
			r_io_submap_sink_in_all(io);
			return true;
		}
		r_io_submap_cut_out (io, map->itv.addr,
				map->itv.addr + map->itv.size - 1);
		r_io_submap_sink_in_all(io);
		return true;
	}
	return false;
}

R_API bool r_io_map_remap_fd (RIO *io, int fd, ut64 addr) {
	RList *maps;
	RIOMap *map;
	bool retval = false;
	maps = r_io_map_get_for_fd (io, fd);
	if (maps) {
		map = r_list_get_n (maps, 0);
		if (map) {
			retval = r_io_map_remap (io, map->id, addr);
		}
		r_list_free (maps);
	}
	return retval;
}

R_API void r_io_map_init(RIO* io) {
	if (io && !io->maps) {
		io->maps = r_oids_new (1, END_OF_MAP_IDS);
		if (io->submaps) {
			r_io_submap_fini(io);
		}
		r_io_submap_init (io);
	}
}

static bool _map_exists_cb(void *user, void *data, ut32 id) {
	RIOMap *check = (RIOMap *)user;
	RIOMap *map = (RIOMap *)data;

	return !!memcmp (check, map, sizeof(RIOMap));
}

// check if a map with exact the same properties exists
R_API bool r_io_map_exists(RIO* io, RIOMap* map) {
	if (!io || !io->maps || !map) {		//more checks here, plz
		return false;
	}
	return !r_oids_foreach(io->maps, _map_exists_cb, map);
}

// check if a map with specified id exists
R_API bool r_io_map_exists_for_id(RIO* io, ut32 id) {
	return !!r_io_map_resolve (io, id);
}

R_API RIOMap* r_io_map_resolve(RIO* io, ut32 id) {
	return io ? (RIOMap *)r_oids_get (io->maps, id) : NULL;
}

R_API RIOMap* r_io_map_add(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size) {
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		return r_io_map_new (io, fd, (flags & desc->flags) | (flags & R_IO_EXEC),
				delta, addr, size);
	}
	return NULL;
}

typedef struct map_get_addr_t {
	RIOMap *map;
	ut64 addr;
} MapGetAddr;

static bool _map_get_paddr_cb (void *user, void *data, ut32 id) {
	MapGetAddr *stuff = (MapGetAddr *)user;
	RIOMap *map = (RIOMap *)data;

	if (map->delta <= stuff->addr &&
	    stuff->addr <= map->delta + map->itv.size - 1) {
		stuff->map = map;
		return false;
	}
	return true;
}

//this should expose mapid only
R_API RIOMap* r_io_map_get_paddr(RIO* io, ut64 paddr) {
	MapGetAddr stuff;
	if (!io) {
		return NULL;
	}

	stuff.addr = paddr;
	stuff.map = NULL;
	r_oids_foreach(io->maps, _map_get_paddr_cb, &stuff);
	return stuff.map;
}

R_API void r_io_map_reset(RIO* io) {
	r_io_map_fini (io);
	r_io_map_init (io);
}

R_API bool r_io_map_del(RIO* io, ut32 id) {
	RIOMap *map;
	if (io && (map = r_oids_take(io->maps, id))) {
		r_io_submap_cut_out (io, map->itv.addr,
				map->itv.addr + map->itv.size - 1);
		r_io_submap_sink_in_all (io);
		free(map->name);
		free(map);
		return true;
	}
	return false;
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	RIOMap *map;
	ut32 od = 0;
	bool ret = false;
	if (!io || !io->maps || !io->submaps) {
		return ret;
	}
	while ((map = r_oids_oget(io->maps, od))) {
		if (map->fd == fd) {
			r_io_submap_cut_out (io, map->itv.addr,
					map->itv.addr + map->itv.size - 1);
			r_oids_odelete (io->maps, od);
			free (map->name);
			free (map);
			ret = true;
		} else {
			od++;
		}
	}
	if (ret) {
		r_io_submap_sink_in_all (io);
	}
	return ret;
}

//return a boolean denoting whether is was possible to priorized
R_API bool r_io_map_priorize(RIO *io, ut32 id) {
	RIOMap *map;
	if (io && io->maps && io->submaps && r_oids_to_front (io->maps, id)) {
		map = r_oids_first (io->maps);
		r_io_submap_repress (io, map);
		return true;
	}
	return false;
}

R_API bool r_io_map_depriorize(RIO *io, ut32 id) {
	RIOMap *map;
	if (io && io->maps && io->submaps && r_oids_to_rear (io->maps, id)) {
		map = r_oids_last (io->maps);
		r_io_submap_cut_out (io, map->itv.addr,
				map->itv.addr + map->itv.size - 1);
		r_io_submap_sink_in_all (io);
		return true;
	}
	return false;
}

typedef struct map_priorize_fd_t {
	RIO *io;
	int fd;
} MapPriorizeFd;

static bool _map_priorize_fd_cb(void *user, void *data, ut32 id) {
	MapPriorizeFd *mpfd = (MapPriorizeFd *)user;
	RIOMap *map = (RIOMap *)data;

	if (map->fd == mpfd->fd) {
		r_io_submap_repress (mpfd->io, map);
		return r_oids_to_front (mpfd->io->maps, id);
	}
	return true;
}

R_API bool r_io_map_priorize_for_fd(RIO* io, int fd) {
	MapPriorizeFd mpfd;
	if (!io || !io->maps) {
		return false;
	}
	mpfd.fd = fd;
	mpfd.io = io;
	return r_oids_foreach_prev (io->maps, _map_priorize_fd_cb, &mpfd);
}

static bool _map_cleanup_cb(void *user, void *data, ut32 id) {
	RIO *io = (RIO *)user;
	RIOMap *map = (RIOMap *)data;

	if (!r_io_desc_get (io, map->fd)) {
		r_oids_delete (io->maps, id);
	}
	return true;
}

//may fix some inconsistencies in io->maps
R_API void r_io_map_cleanup(RIO* io) {
	if (!io || !io->maps) {
		return;
	}
	//remove all maps if no descs exist
	if (!io->files) {
		r_io_map_fini (io);
		r_io_map_init (io);
		return;
	}
	r_oids_foreach_prev (io->maps, _map_cleanup_cb, io);
}

static bool _map_free_cb(void *user, void *data, ut32 id) {
	RIOMap* map = (RIOMap *)data;
	if (map) {
		free (map->name);
		free (map);
	}
	return true;
}

R_API void r_io_map_fini(RIO* io) {
	if (!io) {
		return;
	}
	r_io_submap_fini (io);
	r_oids_foreach (io->maps, _map_free_cb, NULL);
	r_oids_free (io->maps);
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

//TODO: Kill it with fire
R_API RIOMap* r_io_map_add_next_available(RIO* io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, ut64 load_align) {
	RIOMap* map;
	ut32 od = 0;
	ut64 next_addr = addr,
	end_addr = next_addr + size;
	
	if (!io || !io->maps) {
		return NULL;
	}

	while ((map = r_oids_oget (io->maps, od))) {
		ut64 to = r_itv_end (map->itv);
		next_addr = R_MAX (next_addr, to + (load_align - (to % load_align)) % load_align);
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files.

		if (map->fd == fd && ((map->itv.addr <= next_addr && next_addr < to) ||
						r_itv_contain (map->itv, end_addr))) {
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			next_addr = to + (load_align - (to % load_align)) % load_align;
			return r_io_map_add_next_available (io, fd, flags, delta, next_addr, size, load_align);
		}
		od++;
//		break;
	}
	return r_io_map_new (io, fd, flags, delta, next_addr, size);
}

R_API ut64 r_io_map_next_address(RIO* io, ut64 addr) {
	ut32 id = r_io_map_get_next (io, addr);
	RIOMap *map = r_io_map_resolve (io, id);
	return map ? R_MAX (addr, map->itv.addr) : UT64_MAX;
}

typedef struct map_get_for_fd_t {
	RList *maps;
	int fd;
} MapGetForFd;

static bool _map_get_for_fd_cb(void *user, void *data, ut32 id) {
	MapGetForFd *mgffd = (MapGetForFd *)user;
	RIOMap *map = (RIOMap *)data;

	if (map->fd == mgffd->fd) {
		r_list_append (mgffd->maps, map);
	}
	return true;
}

R_API RList* r_io_map_get_for_fd(RIO* io, int fd) {
	MapGetForFd mgffd;
	if (!io || !io->maps) {
		return NULL;
	}
	mgffd.maps = r_list_newf (NULL);
	if (!mgffd.maps) {
		return NULL;
	}
	mgffd.fd = fd;
	r_oids_foreach (io->maps, _map_get_for_fd_cb, &mgffd);
	return mgffd.maps;
}

R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	RIOMap *map;
	if (!newsize || !(map = r_io_map_resolve (io, id))) {
		return false;
	}
	ut64 addr = map->itv.addr;
	if (UT64_MAX - newsize + 1 < addr) {
		map->itv.size = -addr;
		r_io_map_new (io, map->fd, map->flags, map->delta - addr, 0, newsize + addr);
		return true;
	}
	r_io_submap_cut_out (io, map->itv.addr,
			map->itv.addr + map->itv.size - 1);
	map->itv.size = newsize;
	r_io_submap_cut_out (io, map->itv.addr,
			map->itv.addr + map->itv.size - 1);
	r_io_submap_sink_in_all (io);
	return true;
}
