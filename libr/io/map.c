/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "r_io.h"
#include "list.h"

R_API void r_io_map_init(struct r_io_t *io)
{
	INIT_LIST_HEAD(&io->maps);
}

R_API struct r_io_map_t *r_io_map_resolve(struct r_io_t *io, int fd)
{
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_map_t *im = list_entry(pos, struct r_io_map_t, list);
		if (im->fd == fd)
			return im;
	}
	return NULL;
}

/* remove all maps of a fd */
R_API int r_io_map_del(struct r_io_t *io, int fd)
{
	int ret = R_FALSE;
	struct list_head *pos, *n;
	list_for_each_safe(pos, n, &io->maps) {
		struct r_io_map_t *im = list_entry(pos, struct r_io_map_t, list);
		if (im->fd == fd) {
			list_del(&im->list);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API int r_io_map_add(struct r_io_t *io, int fd, int flags, ut64 delta, ut64 offset, ut64 size)
{
	struct r_io_map_t *im = MALLOC_STRUCT(struct r_io_map_t);
	if (im == NULL)
		return R_FALSE;
	list_add_tail(&(im->list), &(io->maps));
	im->fd = fd;
	im->flags = flags;
	im->delta = delta;
	im->from = offset;
	im->to = offset + size;
	return R_TRUE;
}

R_API int r_io_map_read_at(struct r_io_t *io, ut64 off, ut8 *buf, int len)
{
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_map_t *im = list_entry(pos, struct r_io_map_t, list);
		if (im && off >= im->from && off < im->to) {
			r_io_set_fd(io, im->fd);
			return r_io_read_at(io, off-im->from + im->delta, buf, len);
		}
	}
	return -1;
}

R_API int r_io_map_write_at(struct r_io_t *io, ut64 off, const ut8 *buf, int len)
{
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_map_t *im = list_entry(pos, struct r_io_map_t, list);
		if (im && off >= im->from && off < im->to) {
			if (im->flags & R_IO_WRITE) {
				r_io_set_fd(io, im->fd);
				return r_io_write_at(io, off-im->from + im->delta, buf, len);
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

/* TODO: Use r_iter here ?? */
int r_io_map_list(struct r_io_t *io)
{
	int n = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_map_t *im = list_entry(pos, struct r_io_map_t, list);
		printf("0x%08llx 0x%08llx delta=0x%08llx fd=%d flags=%x\n",
			im->from, im->to, im->delta, im->fd, im->flags);
		n++;
	}
	return n;
}

