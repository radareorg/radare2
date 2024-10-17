/* radare - LGPL - Copyright 2023-2024 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include "../io_memory.h"

R_IPI ut64 cyclic_seek(RIO* io, RIODesc *desc, ut64 offset, int whence) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	switch (whence) {
	case 0: offset %= mal->cycle; break;
	case 1: offset += mal->offset; offset %= mal->cycle; break;
	case 2: return UT64_MAX - 1; break;
	}
	return io_memory_lseek (io, desc, offset, whence);
}

static bool cyclic_check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "cyclic://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (cyclic_check (io, pathname, 0)) {
		const int cycle = (int)r_num_math (NULL, pathname + 9);
		if (cycle < 1) {
			R_LOG_ERROR ("Cannot allocate (%s) 0 bytes", pathname + 9);
			return NULL;
		}
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		mal->size = cycle;
		mal->cycle = cycle;
		mal->buf = calloc (1, cycle + 1);
		mal->offset = 0;
		if (mal->buf) {
			return r_io_desc_new (io, &r_io_plugin_cyclic, pathname,
				R_PERM_RW | (rw & R_PERM_X), mode, mal);
		}
		R_LOG_ERROR ("Cannot allocate (%s) %d byte(s)", pathname + 9, mal->size);
		free (mal);
	}
	return NULL;
}

static int cyclic_read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	const int bs = R_MIN (mal->cycle, count);
	int i;
	for (i = 0; i < count; i += bs) {
		const int left = R_MIN (count - i, bs);
		(void) io_memory_lseek (io, desc, mal->offset % mal->cycle, 0);
		(void) io_memory_read (io, desc, buf + i, left);
	}
	return count;
}

RIOPlugin r_io_plugin_cyclic = {
	.meta = {
		.name = "cyclic",
		.author = "pancake",
		.desc = "Cyclic memory, infinite file containing the given size in loop",
		.license = "LGPL-3.0-only",
	},
	.uris = "cyclic://",
	.open = __open,
	.close = io_memory_close,
	.read = cyclic_read,
	.check = cyclic_check,
	.seek = cyclic_seek,
	.write = io_memory_write,
// 	.resize = io_memory_resize // maybe not
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_cyclic,
	.version = R2_VERSION
};
#endif
