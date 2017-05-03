/* radare - LGPL - Copyright 2008-2016 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

// copypasta from RIOMalloc... we can heavily simplify this with RBuffer

typedef struct {
	int fd;
	ut8 *buf;
	int size;
	ut64 offset;
} RIOGzip;

#define RIOMALLOC_FD(x) (((RIOGzip*)x->data)->fd)
#define RIOMALLOC_SZ(x) (((RIOGzip*)x->data)->size)
#define RIOMALLOC_BUF(x) (((RIOGzip*)x->data)->buf)
#define RIOMALLOC_OFF(x) (((RIOGzip*)x->data)->offset)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
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
	if (!fd || !fd->data || !count) {
		return false;
	}
	if (RIOMALLOC_OFF (fd) > RIOMALLOC_SZ (fd)) {
		return false;
	}
	new_buf = malloc (count);
	if (!new_buf) {
		return false;
	}
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
	RIOGzip *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	eprintf ("TODO: Writing changes into gzipped files is not yet supported\n");
	riom = fd->data;
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	ut64 r_offset = offset;
	if (!fd->data) {
		return offset;
	}
	switch (whence) {
	case SEEK_SET:
		r_offset = (offset <= RIOMALLOC_SZ (fd)) ? offset : RIOMALLOC_SZ (fd);
		break;
	case SEEK_CUR:
		r_offset = (RIOMALLOC_OFF (fd) + offset <= RIOMALLOC_SZ (fd)) ?
			RIOMALLOC_OFF (fd) + offset : RIOMALLOC_SZ (fd);
		break;
	case SEEK_END:
		r_offset = RIOMALLOC_SZ (fd);
		break;
	}
	RIOMALLOC_OFF (fd) = r_offset;
	return RIOMALLOC_OFF (fd);
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "gzip://", 7));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		RIOGzip *mal = R_NEW0 (RIOGzip);
		if (!mal) return NULL;
		int len;
		ut8 *data = (ut8*)r_file_slurp (pathname+7, &len);
		mal->buf = r_inflate (data, len, NULL, &mal->size);
		if (mal->buf)
			return r_io_desc_new (io, &r_io_plugin_malloc,
				pathname, rw, mode, mal);
		free (data);
		eprintf ("Cannot allocate (%s) %d bytes\n", pathname+9,
			mal->size);
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_gzip = {
	.name = "gzip",
	.desc = "read/write gzipped files",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_gzip,
	.version = R2_VERSION
};
#endif
