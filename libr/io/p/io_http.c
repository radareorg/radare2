/* radare - LGPL - Copyright 2008-2024 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include "../io_memory.h"

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "http://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		int rlen, code;
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (!mal) {
			return NULL;
		}
		mal->offset = 0;
		mal->buf = (ut8*)r_socket_http_get (pathname, &code, &rlen);
		if (mal->buf && rlen > 0) {
			mal->size = rlen;
			return r_io_desc_new (io, &r_io_plugin_malloc, pathname,
				R_PERM_RW | (rw & R_PERM_X), mode, mal);
		}
		R_LOG_ERROR ("No HTTP response");
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_http = {
	.meta = {
		.name = "http",
		.desc = "Make http get requests",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.uris = "http://",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.seek = io_memory_lseek,
	.write = io_memory_write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_http,
	.version = R2_VERSION
};
#endif
