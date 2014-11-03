/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <r_io.h>
#include <r_util.h>
#include <r_list.h>

R_API int r_io_map_count (RIO *io) {
	return r_list_length (io->maps);
}

R_API RIOMap * r_io_map_new(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size) {
	RIOMap *map = R_NEW (RIOMap);
	if (!map) return NULL;
	map->fd = fd;
	map->flags = flags;
	map->delta = delta;
	map->from = addr;
	map->to = addr + size;
	r_list_append (io->maps, map);
	return map;
}

R_API void r_io_map_init(RIO *io) {
	io->maps = r_list_new ();
}

R_API int r_io_map_sort(void *_a, void *_b) {
	RIOMap *a = _a, *b = _b;
	if (a->from == b->from ){
		ut64 a_sz = a->to - a->from,
			b_sz = b->to - b->from;
		return a_sz < b_sz;
	}
	return a->from < b->from;
}

R_API int r_io_map_write_update(RIO *io, int fd, ut64 addr, ut64 len) {
	int res = R_FALSE;
	RIOMap *map = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd) break;
		map = NULL;
	}

	if (map && map->to < addr+len) {
		res = R_TRUE;
		map->to = addr+len;
	}
	return res;
}

R_API int r_io_map_truncate_update(RIO *io, int fd, ut64 sz) {
	int res = R_FALSE;
	RIOMap *map = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd) break;
		map = NULL;
	}

	if (map) {
		res = R_TRUE;
		map->to = map->from+sz;
	}
	return res;
}

R_API RIOMap *r_io_map_get(RIO *io, ut64 addr) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if ((map->from <= addr) && (addr < map->to))
			return map;
	}
	return NULL;
}

R_API RIOMap *r_io_map_resolve(RIO *io, int fd) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd)
			return map;
	}
	return NULL;
}

R_API RIOMap *r_io_map_resolve_from_list (RList *maps, int fd) {
	RIOMap *map = NULL;
	RListIter *iter;
	if (maps) {
		r_list_foreach (maps, iter, map) {
			if (map->fd == fd)
				return map;
		}
	}
	return map;
}

static RList *r_io_map_get_maps_in_range_prepend(RIO *io, ut64 addr, ut64 endaddr) {
	RIOMap *map;
	RListIter *iter;
	RList *maps = r_list_new ();
	maps->free = NULL;
	r_list_foreach (io->maps, iter, map) {
		if (map->from <= addr && addr < map->to) r_list_append(maps, map);
		//if (map->from == addr && endaddr == map->to) r_list_prepend(maps, map);
		if (map->from < endaddr && endaddr < map->to) r_list_prepend(maps, map);
		if (addr <= map->from && map->to <= endaddr) r_list_prepend(maps, map);
	}
	return maps;
}

R_API RIOMap *r_io_map_resolve_in_range (RIO *io, ut64 addr, ut64 endaddr, int fd) {
	RList *maps;
	RIOMap *map;
	if (!io || !io->maps)
		return NULL;
	maps = r_io_map_get_maps_in_range_prepend (io, addr, endaddr);
	map = r_io_map_resolve_from_list (maps, fd);
	r_list_free (maps);
	return map;
}

R_API RList *r_io_map_get_maps_in_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOMap *map;
	RListIter *iter;
	RList *maps = r_list_new ();
	maps->free = NULL;
	r_list_foreach (io->maps, iter, map) {
		if (map->from <= addr && addr < map->to) r_list_append(maps, map);
		//if (map->from == addr && endaddr == map->to) r_list_append(maps, map);
		if (map->from < endaddr && endaddr < map->to) r_list_append(maps, map);
		if (addr <= map->from && map->to <= endaddr) r_list_append(maps, map);
	}
	return maps;
}

R_API RIOMap * r_io_map_get_first_map_in_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOMap *map = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->from <= addr && addr < map->to) break;
		//if (map->from == addr && endaddr == map->to) r_list_append(maps, map);
		if (map->from < endaddr && endaddr < map->to) break;
		if (addr <= map->from && map->to <= endaddr) break;
		map = NULL;
	}
	return map;
}

R_API int r_io_map_del(RIO *io, int fd) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (fd==-1 || map->fd==fd) {
			r_list_delete (io->maps, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_io_map_del_all(RIO *io, int fd) {
	RIOMap *map;
	RListIter *iter, *tmp;
	ut8 deleted = R_FALSE;
	if (io && io->maps) {
		r_list_foreach_safe (io->maps, iter, tmp, map) {
			if (fd==-1 || map->fd==fd) {
				r_list_delete (io->maps, iter);
				deleted = R_TRUE;
			}
		}
	}
	return deleted;
}

R_API ut64 r_io_map_next(RIO *io, ut64 addr) {
	ut64 next = UT64_MAX;
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->from > addr)
			if (!next || map->from < next)
				next = map->from;
	}
	return next;
}

R_API int r_io_map_del_at(RIO *io, ut64 addr) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->from <= addr && addr < map->to) {
			r_list_delete (io->maps, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API RIOMap *r_io_map_add_next_available(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, ut64 load_align) {
	RIOMap *map;
	RListIter *iter;
	ut64 next_addr = addr,
		 end_addr = next_addr + size;
	r_list_foreach (io->maps, iter, map) {
		next_addr = R_MAX (next_addr, map->to+(load_align - (map->to % load_align)));
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for 
		// memory mapping with multiple files.

		if (map->fd == fd && ((map->from <= next_addr && next_addr < map->to) ||
			(map->from <= end_addr  && end_addr < map->to)) ) {
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			next_addr = map->to + (load_align - (map->to % load_align));
			return r_io_map_add_next_available(io, fd, flags, delta, next_addr, size, load_align);
		} else break;
	}
	return r_io_map_new (io, fd, flags, delta, next_addr, size);
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size) {
	RIOMap *map;
	RListIter *iter;
	ut64 end_addr = addr + size;
	r_list_foreach (io->maps, iter, map) {
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000000
		// keeping (fd, to, from) tuples as separate maps
		if ( map->fd == fd && ((map->from <= addr && addr < map->to) ||
			(map->from <= end_addr  && end_addr < map->to)) )
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			return NULL;
	}
	return r_io_map_new (io, fd, flags, delta, addr, size);
}

R_API int r_io_map_exists_for_offset (RIO *io, ut64 off) {
	int res = R_FALSE;
	RIOMap *im = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) {
		if (im->from <= off && off < im->to) {
			res = R_TRUE;
			break;
		}
	}
	return res;
}

R_API ut64 r_io_map_select(RIO *io, ut64 off) {
	int done = 0;
	ut64 fd = -1;
	ut64 paddr = off;
	RIOMap *im = NULL;
	RListIter *iter;
	ut64 prevfrom = 0LL;
	r_list_foreach (io->maps, iter, im) {
		if (off>=im->from) {
			if (prevfrom) {
				if (im->from<prevfrom)
					r_io_use_fd (io, im->fd);
			} else {
				r_io_use_fd (io, im->fd);
			}
			prevfrom = im->from;
		}
		if (off >= im->from && off < im->to) {
			paddr = off - im->from + im->delta; //-im->from;
			fd = im->fd;
			done = 1;
			if (fd == io->raised)
				break;
		}
	}
	if (done == 0) {
		r_io_use_fd (io, fd);
		r_io_seek (io, -1, R_IO_SEEK_SET);
		return paddr;
	}
	if (fd == -1) {
		r_io_seek (io, off, R_IO_SEEK_SET);
		return off;
	}
	r_io_use_fd (io, fd);
	if (io->debug) /* HACK */
		r_io_seek (io, off, R_IO_SEEK_SET);
	else r_io_seek (io, paddr, R_IO_SEEK_SET);
	r_io_use_fd (io, fd);
	return paddr;
}

R_API ut64 r_io_map_select_current_fd(RIO *io, ut64 off, int fd) {
	int done = 0;
	ut64 paddr = off;
	RIOMap *im = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) {
		if (im->fd != fd) continue;
		if (off >= im->from && off < im->to) {
			paddr = off - im->from + im->delta; //-im->from;
			done = 1;
		}
	}
	if (done == 0) {
		r_io_seek (io, -1, R_IO_SEEK_SET);
		return paddr;
	}
	if (fd == -1) {
		r_io_seek (io, off, R_IO_SEEK_SET);
		return off;
	}
	if (io->debug) /* HACK */
		r_io_seek (io, off, R_IO_SEEK_SET);
	else r_io_seek (io, paddr, R_IO_SEEK_SET);
	return paddr;
}

R_API int r_io_map_overlaps (RIO *io, RIODesc *fd, RIOMap *map) {
	RListIter *iter;
	RIOMap *im = NULL;
	ut64 off = map->from;
	if (!fd) return R_FALSE;
	r_list_foreach (io->maps, iter, im) {
		if (im == map) continue;
		if (off >= im->from && off < im->to) {
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API void r_io_map_list (RIO *io) {
	RIOMap *map;
	RListIter *iter;
	if (io && io->maps && io->printf) {
		r_list_foreach (io->maps, iter, map) {
			if (map)
				io->printf ("%i +0x%"PFMT64x" 0x%"PFMT64x" - 0x%"PFMT64x" ; %s\n", map->fd, map->delta, map->from, map->to, r_str_rwx_i (map->flags));
		}
	}
}
