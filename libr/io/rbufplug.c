/* radare - LGPL - Copyright 2017 - pancake */

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
	return r_buf_write_at (b, b->cur, buf, count);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RBuffer *b = fd->data;
	return r_buf_read_at (b, b->cur, buf, count);
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

RIOPlugin r_io_plugin_rbuf = {
	.name = "rbuf",
	.desc = "Internal RBuffer IO plugin",
	.license = "MIT",
	.close = __close,
	.read = __read,
	.lseek = __lseek,
	.write = __write
};

R_API RIODesc *r_io_open_buffer(RIO *io, RBuffer *buf) {
	RIODesc *desc = r_io_desc_new (io, &r_io_plugin_rbuf, "rbuf", 7, 0, buf);
	if (desc) {
		r_io_map_new (io, desc->fd, 7, 0, 0, r_buf_size (buf));
		r_io_desc_add (io, desc);
		r_io_use_desc (io, desc);
	}
	return desc;
}

