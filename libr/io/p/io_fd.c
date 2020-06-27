/* radare - LGPL - Copyright 2020 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	ut32 size;
} RIOMalloc;

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		return write (mal->fd, buf, count);
	}
	return -1;
}

static bool __resize(RIO *io, RIODesc *desc, ut64 count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		return ftruncate (mal->fd, count) == 0;
	}
	return false;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		return read (mal->fd, buf, count);
	}
	return -1;
}

static int __close(RIODesc *desc) {
	// dont close, could be problematic in self://
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *desc, ut64 offset, int whence) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		return lseek (mal->fd, offset, whence);
	}
	return 0;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return !strncmp (pathname, "fd://", 4);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (mal) {
			mal->fd = r_num_math (NULL, pathname + 4);
			if (((int)mal->fd) < 0) {
				free (mal);
				eprintf ("Invalid filedescriptor.\n");
				return NULL;
			}
		}
		return r_io_desc_new (io, &r_io_plugin_fd, pathname, R_PERM_RW | rw, mode, mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_fd = {
	.name = "fd",
	.desc = "Local process filedescriptor IO",
	.uris = "fd://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_fd,
	.version = R2_VERSION
};
#endif
