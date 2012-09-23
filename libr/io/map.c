/* radare - LGPL - Copyright 2008-2012 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <r_io.h>
#include <r_list.h>

R_API void r_io_map_init(struct r_io_t *io) {
	io->maps = r_list_new ();
}

R_API RIOMap *r_io_map_resolve(struct r_io_t *io, int fd) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd)
			return map;
	}
	return NULL;
}

R_API int r_io_map_del(struct r_io_t *io, int fd) {
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

R_API RIOMap *r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 offset, ut64 size) {
	RIOMap *im = R_NEW (RIOMap);
	if (!im) return NULL;
	im->fd = fd;
	im->flags = flags;
	im->delta = delta;
	im->from = offset;
	im->to = offset + size;
	r_list_append (io->maps, im);
	return im;
}

R_API int r_io_map_select(RIO *io, ut64 off) {
	int done = 0;
	ut64 fd = -1;
	st32 delta = 0;
	RIOMap *im = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) {
		if (off >= im->from && off < im->to) {
			delta = off - im->from + im->delta;
			fd = im->fd;
			done = 1;
			if (fd == io->raised)
				break;
		}
	}
	if (done == 0) {
		r_io_set_fdn (io, fd);
		r_io_seek (io, -1, R_IO_SEEK_SET);
		return off;
	}
	if (fd != -1) {
		r_io_set_fdn (io, fd);
		if (io->debug) /* HACK */
			r_io_seek (io, off, R_IO_SEEK_SET);
		else r_io_seek (io, delta, R_IO_SEEK_SET);
		return 0;
	}
	r_io_seek (io, off, R_IO_SEEK_SET);
	return R_FALSE;
}
