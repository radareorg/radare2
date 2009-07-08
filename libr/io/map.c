/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "r_io.h"
#include "list.h"


#if 0
static int maps_n = 0;
static int maps[10];
#endif

void r_io_map_init(struct r_io_t *io)
{
	INIT_LIST_HEAD(&io->maps);
}

int r_io_map_rm(struct r_io_t *io, int fd)
{
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_maps_t *im = list_entry(pos, struct r_io_maps_t, list);
		if (im->fd == fd) {
			/* FREE THIS */
			r_io_handle_close(io,
				fd, r_io_handle_resolve_fd(io, fd));
			fprintf(stderr, "r_io_map_rm: TODO\n");
			return 0;
		}
	}
	fprintf(stderr, "Not found\n");
	return 0;
}

int r_io_map_list(struct r_io_t *io)
{
	int n = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->maps) {
		struct r_io_maps_t *im = list_entry(pos, struct r_io_maps_t, list);
		if (im->file[0] != '\0') {
			printf("0x%08llx 0x%08llx %s\n",
				im->from, im->to, im->file);
			n++;
		}
	}
	return n;
}

int r_io_map(struct r_io_t *io, const char *file, ut64 offset)
{
	struct r_io_maps_t *im;
	int fd = r_io_open(io, file, R_IO_READ, 0644);
	if (fd == -1)
		return -1;
	im = MALLOC_STRUCT(struct r_io_maps_t);
//(struct r_io_maps_t*)malloc(sizeof(struct r_io_maps_t));
	if (im == NULL) {
		r_io_close(io, fd);
		return -1;
	}
	im->fd = fd;
	strncpy(im->file, file, 127);
	im->from = offset;
	im->to   = offset+lseek(fd, 0, SEEK_END);
	list_add_tail(&(im->list), &(io->maps));
	return fd;
}

int r_io_map_read_at(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len)
{
	struct list_head *pos;

	return 0;
	/* XXX This makes radare segfault ?? */
	if (io == NULL) {
		return 0;
	}
	list_for_each_prev(pos, &io->maps) {
		struct r_io_maps_t *im = list_entry(pos, struct r_io_maps_t, list);
		/* segfaults here coz im is invalid */
		if (im->file && im->file[0] != '\0' && off >= im->from && off < im->to) {
			r_io_lseek(io, im->fd, off-im->from, SEEK_SET);
			return r_io_read(io, im->fd, buf, len);
		}
	}
	return 0;
}

int r_io_map_write_at(struct r_io_t *io, ut64 off, const ut8 *buf, ut64 len)
{
	struct list_head *pos;

	list_for_each_prev(pos, &io->maps) {
		struct r_io_maps_t *im = list_entry(pos, struct r_io_maps_t, list);
		if (im->file[0] != '\0' && off >= im->from && off < im->to) {
			r_io_lseek(io, im->fd, off-im->from, SEEK_SET);
			return r_io_write(io, im->fd, buf, len);
		}
	}
	return 0;
}

int r_io_map_read_rest(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len)
{
	struct list_head *pos;

	list_for_each_prev(pos, &io->maps) {
		struct r_io_maps_t *im = list_entry(pos, struct r_io_maps_t, list);
		if (im->file[0] != '\0' && off+len >= im->from && off < im->to) {
			lseek(im->fd, 0, SEEK_SET);
			return read(im->fd, buf+(im->from-(off+len)), len);
		}
	}
	return 0;
}
