/* radare - LGPL - Copyright 2008-2013 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
	ut64 offset;
} RIOMalloc;

#define RIOMALLOC_FD(x) (((RIOMalloc*)x->data)->fd)
#define RIOMALLOC_SZ(x) (((RIOMalloc*)x->data)->size)
#define RIOMALLOC_BUF(x) (((RIOMalloc*)x->data)->buf)
#define RIOMALLOC_OFF(x) (((RIOMalloc*)x->data)->offset)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (fd == NULL || fd->data == NULL)
		return -1;
	if (RIOMALLOC_OFF (fd) > RIOMALLOC_SZ (fd))
		return -1;
	if (RIOMALLOC_OFF (fd) + count > RIOMALLOC_SZ (fd))
		count -= (RIOMALLOC_OFF (fd) + count-(RIOMALLOC_SZ (fd)));

	if (count > 0) {
		memcpy (RIOMALLOC_BUF (fd) + RIOMALLOC_OFF (fd), buf, count);
		RIOMALLOC_OFF (fd) += count;
		return count;
	}
	return -1;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (fd == NULL || fd->data == NULL)
		return -1;
	if (RIOMALLOC_OFF (fd) > RIOMALLOC_SZ (fd))
		return -1;
	if (RIOMALLOC_OFF (fd) + count >= RIOMALLOC_SZ (fd))
		count = RIOMALLOC_SZ (fd) - RIOMALLOC_OFF (fd);
	memcpy (buf, RIOMALLOC_BUF (fd) + RIOMALLOC_OFF (fd), count);
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
	ut64 r_offset = offset;
	switch (whence) {
	case SEEK_SET:
		r_offset = (offset <= RIOMALLOC_SZ (fd)) ? offset : RIOMALLOC_SZ (fd);
		break;
	case SEEK_CUR:
		r_offset = (RIOMALLOC_OFF (fd) + offset <= RIOMALLOC_SZ (fd)) ? RIOMALLOC_OFF (fd) + offset : RIOMALLOC_SZ (fd);
		break;
	case SEEK_END:
		r_offset = RIOMALLOC_SZ (fd);
		break;
	}
	RIOMALLOC_OFF (fd) = r_offset;
	return RIOMALLOC_OFF (fd);
}

static int __plugin_open(struct r_io_t *io, const char *pathname) {
	return (
		(!memcmp (pathname, "malloc://", 9)) ||
		(!memcmp (pathname, "hex://", 6))
	);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname)) {
		RIOMalloc *mal = R_NEW (RIOMalloc);
		mal->fd = -2; /* causes r_io_desc_new() to set the correct fd */
		if (!memcmp (pathname, "hex://", 6)) {
			mal->size = strlen (pathname);
			mal->buf = malloc (mal->size);
			mal->offset = 0;
			memset (mal->buf, 0, mal->size);
			mal->size = r_hex_str2bin (pathname+6, mal->buf);
		} else {
			mal->size = r_num_math (NULL, pathname+9);
			mal->offset = 0;
			if (((int)(mal->size))>0) {
				mal->buf = malloc (mal->size);
				memset (mal->buf, '\0', mal->size);
			} else {
				eprintf ("Cannot allocate (%s) 0 bytes\n", pathname+9);
				return NULL;
			}
		}
		if (mal->buf != NULL) {
			RETURN_IO_DESC_NEW (&r_io_plugin_malloc,
				mal->fd, pathname, rw, mode,mal);
		}
		eprintf ("Cannot allocate (%s) %d bytes\n", pathname+9,
			mal->size);
		free (mal);
	}
	return NULL;
}

struct r_io_plugin_t r_io_plugin_malloc = {
	.name = "malloc",
	.desc = "memory allocation (malloc://1024 hex://cd8090)",
	.license = "LGPL3",
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
