/* radare - LGPL - Copyright 2020 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <r_cons.h>
#include <sys/types.h>

#if __WINDOWS__
#define FDURI "handle://"
#else
#define FDURI "fd://"
#endif

typedef struct {
	int fd;
} RIOFdata;

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RIOFdata *fdd = (RIOFdata*)desc->data;
	if (fdd) {
		return write (fdd->fd, buf, count);
	}
	return -1;
}

static bool __resize(RIO *io, RIODesc *desc, ut64 count) {
	RIOFdata *fdd = (RIOFdata*)desc->data;
	if (fdd) {
		return ftruncate (fdd->fd, count) == 0;
	}
	return false;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOFdata *fdd = (RIOFdata*)desc->data;
	if (fdd) {
		r_cons_break_push (NULL, NULL);
		int res = read (fdd->fd, buf, count);
		r_cons_break_pop ();
		return res;
	}
	return -1;
}

static int __close(RIODesc *desc) {
	R_FREE (desc->data);
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *desc, ut64 offset, int whence) {
	RIOFdata *fdd = (RIOFdata*)desc->data;
	if (fdd) {
		return lseek (fdd->fd, offset, whence);
	}
	return 0;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return !strncmp (pathname, FDURI, strlen (FDURI));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_sandbox_enable (false)) {
		eprintf ("Do not permit " FDURI " in sandbox mode.\n");
		return NULL;
	}
	if (!__check (io, pathname, 0)) {
		return NULL;
	}
	RIOFdata *fdd = R_NEW0 (RIOFdata);
	if (fdd) {
		fdd->fd = r_num_math (NULL, pathname + strlen (FDURI));
#if __WINDOWS__
		fdd->fd = _open_osfhandle (fdd->fd, 0);
#endif
		if (fdd->fd < 0) {
			free (fdd);
			eprintf ("Invalid filedescriptor.\n");
			return NULL;
		}
	}
	return r_io_desc_new (io, &r_io_plugin_fd, pathname, R_PERM_RW | rw, mode, fdd);
}

RIOPlugin r_io_plugin_fd = {
#if __WINDOWS__
	.name = "handle",
	.desc = "Local process file handle IO",
#else
	.name = "fd",
	.desc = "Local process filedescriptor IO",
#endif
	.uris = FDURI,
	.license = "MIT",
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
