/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "r_io.h"
#include "r_list.h"

R_API void r_io_map_init(struct r_io_t *io) {
	io->maps = r_list_new ();
}

R_API struct r_io_map_t *r_io_map_resolve(struct r_io_t *io, int fd) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd)
			return map;
	}
	return NULL;
}

R_API int r_io_map_del(struct r_io_t *io, int fd) {
	int ret = R_FALSE;
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (fd==-1 || map->fd==fd) {
			r_list_delete (io->maps, iter);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API int r_io_map_add(struct r_io_t *io, int fd, int flags, ut64 delta, ut64 offset, ut64 size) {
	RIOMap *im = R_NEW (RIOMap);
	if (im == NULL)
		return R_FALSE;
	im->fd = fd;
	im->flags = flags;
	im->delta = delta;
	im->from = offset;
	im->to = offset + size;
	r_list_append (io->maps, im);
	return R_TRUE;
}

R_API int r_io_map_read_at(struct r_io_t *io, ut64 off, ut8 *buf, int len) {
	RIOMap *im;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) { // _prev?
		if (im && off >= im->from && off < im->to) {
			r_io_set_fdn (io, im->fd);
			return r_io_read_at (io, off-im->from + im->delta, buf, len);
		}
	}
	return -1;
}

R_API int r_io_map_write_at(struct r_io_t *io, ut64 off, const ut8 *buf, int len) {
	RIOMap *im;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) {
		if (im && off >= im->from && off < im->to) {
			if (im->flags & R_IO_WRITE) {
				r_io_set_fdn (io, im->fd);
				return r_io_write_at (io, off-im->from + im->delta, buf, len);
			} else return -1;
		}
	}
	return 0;
}

// DEPRECATE ??? DEPREACATE

#if 0
int r_io_map_read_rest(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len)
{
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_map_t *im = list_entry(pos, struct r_io_map_t, list);
		if (im->file[0] != '\0' && off+len >= im->from && off < im->to) {
			lseek(im->fd, 0, SEEK_SET);
// XXX VERY BROKEN
			return read(im->fd, buf+(im->from-(off+len)), len);
		}
	}
	return 0;
}
#endif
