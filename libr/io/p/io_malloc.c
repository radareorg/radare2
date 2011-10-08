/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
} RIOMalloc;

#define RIOMALLOC_FD(x) (((RIOMalloc*)x->data)->fd)
#define RIOMALLOC_SZ(x) (((RIOMalloc*)x->data)->size)
#define RIOMALLOC_BUF(x) (((RIOMalloc*)x->data)->buf)

static int __write(struct r_io_t *io, RIODesc *fd, const ut8 *buf, int count) {
	if (fd == NULL || fd->data == NULL)
		return -1;
	if (io->off+count >= RIOMALLOC_SZ (fd))
		return -1;
	memcpy (RIOMALLOC_BUF (fd)+io->off, buf, count);
	return count;
}

static int __read(struct r_io_t *io, RIODesc *fd, ut8 *buf, int count) {
	if (fd == NULL || fd->data == NULL)
		return -1;
	if (io->off+count >= RIOMALLOC_SZ (fd))
		return -1;
	memcpy (buf, RIOMALLOC_BUF (fd)+io->off, count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOMalloc *riom;
	if (fd == NULL || fd->data == NULL)
		return -1;
	riom = fd->data;
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RIOMALLOC_SZ (fd);
	}
	return offset;
}

static int __plugin_open(struct r_io_t *io, const char *pathname) {
	return (!memcmp (pathname, "malloc://", 9));
}

static inline int getmalfd (RIOMalloc *mal) {
	return 0xfffffff & (int)(size_t)mal->buf;
}

static RIODesc *__open(struct r_io_t *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname)) {
		RIOMalloc *mal = R_NEW (RIOMalloc);
		mal->fd = getmalfd (mal);
		mal->size = atoi (pathname+9);
		if ((mal->size)>0) {
			mal->buf = malloc (mal->size);
			if (mal->buf != NULL) {
				memset (mal->buf, '\0', mal->size);
				return r_io_desc_new (&r_io_plugin_malloc, mal->fd, pathname, rw, mode, mal);
			}
		}
		eprintf ("Cannot allocate (%s) %d bytes\n", pathname+9, mal->size);
		free (mal);
	}
	return NULL;
}

struct r_io_plugin_t r_io_plugin_malloc = {
	.name = "malloc",
        .desc = "memory allocation (malloc://1024)",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_malloc
};
#endif
