/* radare - LGPL - Copyright 2008-2016 - pancake */

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
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	if (RIOMALLOC_OFF (fd) > RIOMALLOC_SZ (fd)) {
		return -1;
	}
	if (RIOMALLOC_OFF (fd) + count > RIOMALLOC_SZ (fd)) {
		count -= (RIOMALLOC_OFF (fd) + count-(RIOMALLOC_SZ (fd)));
	}
	if (count > 0) {
		memcpy (RIOMALLOC_BUF (fd) + RIOMALLOC_OFF (fd), buf, count);
		RIOMALLOC_OFF (fd) += count;
		return count;
	}
	return -1;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	ut8 * new_buf = NULL;
	if (!fd || !fd->data || count == 0) {
		return false;
	}
	if (RIOMALLOC_OFF (fd) > RIOMALLOC_SZ (fd)) {
		return false;
	}
	new_buf = malloc (count);
	if (!new_buf) return -1;
	memcpy (new_buf, RIOMALLOC_BUF (fd), R_MIN (count, RIOMALLOC_SZ (fd)));
	if (count > RIOMALLOC_SZ (fd)) {
		memset (new_buf + RIOMALLOC_SZ (fd), 0, count - RIOMALLOC_SZ (fd));
	}
	free (RIOMALLOC_BUF (fd));
	RIOMALLOC_BUF (fd) = new_buf;
	RIOMALLOC_SZ (fd) = count;
	return true;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (!fd || !fd->data) {
		return -1;
	}
	if (RIOMALLOC_OFF (fd) > RIOMALLOC_SZ (fd)) {
		return -1;
	}
	if (RIOMALLOC_OFF (fd) + count >= RIOMALLOC_SZ (fd)) {
		count = RIOMALLOC_SZ (fd) - RIOMALLOC_OFF (fd);
	}
	memcpy (buf, RIOMALLOC_BUF (fd) + RIOMALLOC_OFF (fd), count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	ut64 r_offset = offset;
	if (!fd || !fd->data) {
		return offset;
	}
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

static bool __check(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "malloc://", 9)) || (!strncmp (pathname, "hex://", 6));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname,0)) {
		RIOMalloc *mal = R_NEW (RIOMalloc);
//		mal->fd = -2; /* causes r_io_desc_new() to set the correct fd */
		if (!strncmp (pathname, "hex://", 6)) {
			mal->size = strlen (pathname);
			mal->buf = malloc (mal->size + 1);
			if (!mal->buf) {
				free (mal);
				return NULL;
			}
			mal->offset = 0;
			memset (mal->buf, 0, mal->size);
			mal->size = r_hex_str2bin (pathname + 6, mal->buf);
			if ((int)mal->size < 1) {
				R_FREE (mal->buf);
			}
		} else {
			mal->size = r_num_math (NULL, pathname + 9);
			if (((int)mal->size) <= 0) {
				free (mal);
				eprintf ("Cannot allocate (%s) 0 bytes\n", pathname + 9);
				return NULL;
			}
			mal->offset = 0;
			mal->buf = calloc (1, mal->size + 1);
		}
		if (mal->buf) {
			mal->fd = (int) mal->buf;
			return r_io_desc_new (io, &r_io_plugin_malloc,
				 pathname, rw, mode,mal);
		}
		eprintf ("Cannot allocate (%s) %d bytes\n", pathname + 9, mal->size);
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_malloc = {
	.name = "malloc",
	.desc = "memory allocation (malloc://1024 hex://cd8090)",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_malloc,
	.version = R2_VERSION
};
#endif
