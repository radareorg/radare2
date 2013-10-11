/* radare - LGPL - Copyright 2008-2012 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <r_io.h>
#include <r_list.h>

R_API void r_io_map_init(RIO *io) {
	io->maps = r_list_new ();
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
		if (map->from == addr) {
			r_list_delete (io->maps, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		// cannot map two files on the same address
		if (map->from == addr)
			return NULL;
	}
	map = R_NEW (RIOMap);
	if (!map) return NULL;
	map->fd = fd;
	map->flags = flags;
	map->delta = delta;
	map->from = addr;
	map->to = addr + size;
	r_list_append (io->maps, map);
	return map;
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
