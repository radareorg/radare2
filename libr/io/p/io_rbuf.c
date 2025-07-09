/* radare2 - LGPL - Copyright 2017-2025 - pancake, condret */

#include <r_io.h>

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	R_RETURN_VAL_IF_FAIL (io && fd && buf && fd->data, -1);
	if (count >= 0 && fd->perm & R_PERM_W) {
		RBuffer *b = fd->data;
		return r_buf_write (b, buf, count);
	}
	return -1;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	R_RETURN_VAL_IF_FAIL (io && fd && buf, -1);
	RBuffer *b = fd->data;
	return r_buf_read (b, buf, count);
}

static bool __close(RIODesc *fd) {
	return true;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	RBuffer *buf = fd->data;
	return r_buf_seek (buf, offset, whence);
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "rbuf://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	R_RETURN_VAL_IF_FAIL (io && pathname, NULL);
	if (r_sandbox_enable (false)) {
		R_LOG_ERROR ("rbuf:// doesnt work with sandbox enabled");
		return NULL;
	}
	RBuffer *buf = (RBuffer *)(void *)(size_t)r_num_get (NULL, pathname + 7);
	if (buf) {
		return r_io_desc_new (io, &r_io_plugin_rbuf, pathname, rw, 0, buf);
	}
	return NULL;
}

RIOPlugin r_io_plugin_rbuf = {
	.meta = {
		.name = "rbuf",
		.desc = "Unsafe RBuffer IO plugin",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.uris = "rbuf://",
	.open = __open,
	.close = __close,
	.read = __read,
	.seek = __lseek,
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
