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
} RIOMalloc;

#define RIOHTTP_FD(x) (((RIOMalloc*)x->data)->fd)
#define RIOHTTP_SZ(x) (((RIOMalloc*)x->data)->size)
#define RIOHTTP_BUF(x) (((RIOMalloc*)x->data)->buf)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	if (io->off + count > RIOHTTP_SZ (fd)) {
		return -1;
	}
	memcpy (RIOHTTP_BUF (fd)+io->off, buf, count);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	unsigned int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	sz = RIOHTTP_SZ (fd);
	if (io->off >= sz) {
		return -1;
	}
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	memcpy (buf, RIOHTTP_BUF (fd) + io->off, count);
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

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RIOHTTP_SZ (fd);
	}
	return offset;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "http://", 7));
}

static inline int getmalfd (RIOMalloc *mal) {
	return (UT32_MAX >> 1) & (int)(size_t)mal->buf;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	char *out;
	int rlen, code;
	if (__plugin_open (io, pathname, 0)) {
		out = r_socket_http_get (pathname, &code, &rlen);
		if (out && rlen>0) {
			RIOMalloc *mal = R_NEW0 (RIOMalloc);
			if (!mal) return NULL;
			mal->size = rlen;
			mal->buf = malloc (mal->size+1);
			if (!mal->buf) {
				free (mal);
				return NULL;
			}
			if (mal->buf != NULL) {
				mal->fd = getmalfd (mal);
				memcpy (mal->buf, out, mal->size);
				free (out);
				return r_io_desc_new (io, &r_io_plugin_http,
					pathname, rw, mode, mal);
			}
			eprintf ("Cannot allocate (%s) %d bytes\n", pathname+9, mal->size);
			free (mal);
		}
		free (out);
	}
	return NULL;
}

RIOPlugin r_io_plugin_http = {
	.name = "http",
        .desc = "http get (http://rada.re/)",
	.license = "LGPL3",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_http,
	.version = R2_VERSION
};
#endif
