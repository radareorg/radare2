/* radare - LGPL - Copyright 2022-2024 - pancake */

#include <r_lib.h>
#include "../io_memory.h"

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "xalz://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		const char *diskpath = r_str_trim_head_ro (pathname + 7);
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (!mal) {
			return NULL;
		}
		size_t sz;
		int outsize;
		char *data = r_file_slurp (diskpath, &sz);
		int consumed;
		if (data) {
			ut32 osz = r_read_le32 (data + 8);
			// create buffer
			ut8 *obuf = r_inflate_lz4 ((const ut8*)data + 0xc, (uint32_t) sz - 0xc, &consumed, &outsize);
			if (obuf) {
				if (osz != outsize) {
					R_LOG_WARN ("Invalid decompressed size");
				}
				mal->buf = obuf;
				mal->size = osz;
				return r_io_desc_new (io, &r_io_plugin_xalz, diskpath,
					R_PERM_RW | (rw & R_PERM_X), mode, mal);
			}
			free (data);
		}
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_xalz = {
	.meta = {
		.name = "xalz",
		.desc = "XAmarin LZ4 assemblies",
		.author = "pancake",
		.license = "MIT",
	},
	.uris = "xalz://",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.seek = io_memory_lseek,
	.write = io_memory_write,
	.resize = io_memory_resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_xalz,
	.version = R2_VERSION
};
#endif
