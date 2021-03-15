/* radare - LGPL - Copyright 2008-2021 - pancake */

#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include "../io_memory.h"

static bool __check(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "slurp://", 8)
		|| !strncmp (pathname, "malloc://", 9))
		|| (!strncmp (pathname, "hex://", 6));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (!mal) {
			return NULL;
		}
		if (!strncmp (pathname, "slurp://", 8)) {
			size_t size;
			char *buf = r_file_slurp (pathname + 8, &size);
			if (!buf || size < 1) {
				free (mal);
				return NULL;
			}
			mal->size = size;
			mal->buf = (ut8*)buf;
		} else if (!strncmp (pathname, "hex://", 6)) {
			mal->size = strlen (pathname);
			mal->buf = calloc (1, mal->size + 1);
			if (!mal->buf) {
				free (mal);
				return NULL;
			}
			mal->size = r_hex_str2bin (pathname + 6, mal->buf);
			if ((int)mal->size < 1) {
				R_FREE (mal->buf);
			}
		} else {
			mal->size = r_num_math (NULL, pathname + 9);
			if (((int)mal->size) <= 0) {
				free (mal);
				eprintf ("Cannot allocate (%s) 0 bytes\n", pathname + 9);
				return NULL;
			}
			mal->buf = calloc (1, mal->size + 1);
		}
		mal->offset = 0;
		if (mal->buf) {
			return r_io_desc_new (io, &r_io_plugin_malloc, pathname, R_PERM_RW | rw, mode, mal);
		}
		eprintf ("Cannot allocate (%s) %d byte(s)\n", pathname + 9, mal->size);
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_malloc = {
	.name = "malloc",
	.desc = "Memory allocation plugin",
	.uris = "malloc://,hex://,slurp://",
	.license = "LGPL3",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.lseek = io_memory_lseek,
	.write = io_memory_write,
	.resize = io_memory_resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_malloc,
	.version = R2_VERSION
};
#endif
