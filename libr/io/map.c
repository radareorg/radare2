/* radare - LGPL - Copyright 2008-2012 pancake<nopcode.org> */

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
	/* No _safe loop necessary because we return immediately after the delete. */
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
	//ut64 delta = 0;
	ut64 fd = -1;//io->fd;
	st32 delta = 0;
	RIOMap *im = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) { // _prev?
		if (off >= im->from && off < im->to) {
			delta = off - im->from + im->delta;
			fd = im->fd;
			if (fd == io->raised)
				break;
		}
	}
	if (fd != -1) {
		r_io_set_fdn (io, fd);
		//eprintf ("seek ret %d = %llx\n", delta, 
		r_io_seek (io, delta, R_IO_SEEK_SET);
		return R_TRUE;
	} else r_io_seek (io, off, R_IO_SEEK_SET);
	return R_FALSE;
}

#if 0
int r_io_map_read_rest(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len) {
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
