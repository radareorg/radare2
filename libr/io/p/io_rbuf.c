/* radare2 - LGPL - Copyright 2017 - pancake, condret */

#include "r_io.h"
#include "r_lib.h"
#include <r_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	RBuffer *b = fd->data;
	return r_buf_write (b, buf, count);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RBuffer *b = fd->data;
	return r_buf_read (b, buf, count);
}

static int __close(RIODesc *fd) {
	RBuffer *b = fd->data;
	r_buf_free (b);
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	RBuffer *buf = fd->data;
	return r_buf_seek (buf, offset, whence);
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "rbuf://", 7));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	RIODesc *desc;
	RBuffer *buf = r_buf_new ();
	if (buf && (desc = r_io_desc_new (io, &r_io_plugin_rbuf, pathname, 7, 0, buf))) {
		return desc;
	}
	r_buf_free (buf);
	return NULL;
}

RIOPlugin r_io_plugin_rbuf = {
	.name = "rbuf",
	.desc = "RBuffer IO plugin",
	.uris = "rbuf://",
	.license = "LGPL",
	.open = __open,
	.close = __close,
	.read = __read,
	.lseek = __lseek,
	.write = __write,
	.check = __check
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_rbuf,
	.version = R2_VERSION
};
#endif
