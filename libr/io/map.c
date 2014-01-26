/* radare - LGPL - Copyright 2008-2013 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <r_io.h>
#include <r_list.h>


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


R_API RIOMap *r_io_map_get(RIO *io, ut64 addr) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->from == addr)
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

R_API RList *r_io_get_maps_in_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOMap *map;
	RListIter *iter;
	RList *maps = r_list_new ();
	r_list_foreach (io->maps, iter, map) {
		if (map->from <= addr && addr < map->to) r_list_append(maps, map);
		//if (map->from == addr && endaddr == map->to) r_list_append(maps, map);
		if (map->from < endaddr && endaddr < map->to) r_list_append(maps, map);
		if (addr <= map->from && map->to <= endaddr) r_list_append(maps, map);
	}
	return maps;
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

R_API ut64 r_io_map_next(RIO *io, ut64 addr) {
	ut64 next = 0;
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
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		if ((map->from <= next_addr && next_addr < map->to) ||
			(map->from <= end_addr  && end_addr < map->to) ) {
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			next_addr = map->to + (load_align - (map->to % load_align));
			return r_io_map_add_next_available(io, fd, flags, delta, next_addr, size, load_align);
		}
	}
	return r_io_map_new (io, fd, flags, delta, next_addr, size);
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size) {
	RIOMap *map;
	RListIter *iter;
	ut64 end_addr = addr + size;
	r_list_foreach (io->maps, iter, map) {
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000000
		if ((map->from <= addr && addr < map->to) ||
			(map->from <= end_addr  && end_addr < map->to) )
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			return NULL;
	}
	return r_io_map_new (io, fd, flags, delta, addr, size);
}

R_API ut64 r_io_map_select_current_fd(RIO *io, ut64 addr) {
	RIOMap *im = NULL, *map = NULL;
	RListIter *iter;

	r_list_foreach (io->maps, iter, im) {
		if (map && map->fd == io->fd->fd) {
			map = im;
			break;
		}
	}

	if (map) {
		return r_io_seek (io, addr, R_IO_SEEK_SET);
	}
	return -1;
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
					r_io_set_fdn (io, im->fd);
			} else {
				r_io_set_fdn (io, im->fd);
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
		r_io_set_fdn (io, fd);
		r_io_seek (io, -1, R_IO_SEEK_SET);
		return paddr;
	}
	if (fd == -1) {
		r_io_seek (io, off, R_IO_SEEK_SET);
		return off;
	}
	r_io_set_fdn (io, fd);
	if (io->debug) /* HACK */
		r_io_seek (io, off, R_IO_SEEK_SET);
	else r_io_seek (io, paddr, R_IO_SEEK_SET);
	r_io_set_fdn (io, fd);
	return paddr;
}
