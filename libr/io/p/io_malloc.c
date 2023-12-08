/* radare - LGPL - Copyright 2008-2023 - pancake, condret */

#include <r_io.h>
#include <r_lib.h>
#include "../io_memory.h"

static bool __check(RIO *io, const char *pathname, bool many) {
	const char *uris[] = {
		"slurp://", "malloc://", "hex://", "stdin://", NULL
	};
	size_t i = 0;
	while (uris[i]) {
		if (r_str_startswith (pathname, uris[i])) {
			return true;
		}
		i++;
	}
	return false;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (!mal) {
			return NULL;
		}
		if (r_str_startswith (pathname, "slurp://")) {
			size_t size;
			char *buf = r_file_slurp (pathname + 8, &size);
			if (!buf || size < 1) {
				free (mal);
				free (buf);
				return NULL;
			}
			mal->size = size;
			mal->buf = (ut8*)buf;
		} else if (r_str_startswith (pathname, "stdin://")) {
			int size;
			char *buf = r_stdin_slurp (&size);
			if (!buf || size < 1) {
				free (mal);
				free (buf);
				return NULL;
			}
			mal->size = size;
			mal->buf = (ut8*)buf;
		} else if (r_str_startswith (pathname, "hex://")) {
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
			if (((int)mal->size) < 1) {
				free (mal);
				R_LOG_ERROR ("Cannot allocate (%s) 0 bytes", pathname + 9);
				return NULL;
			}
			mal->buf = calloc (1, mal->size + 1);
		}
		mal->offset = 0;
		if (mal->buf) {
			return r_io_desc_new (io, &r_io_plugin_malloc, pathname,
				R_PERM_RW | (rw & R_PERM_X), mode, mal);
		}
		R_LOG_ERROR ("Cannot allocate (%s) %d byte(s)", pathname + 9, mal->size);
		free (mal);
	}
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	const int ret = io_memory_write (io, fd, buf, count);
	if (ret == -1 || !r_str_startswith (fd->uri, "hex://")) {
		return ret;
	}
	RIOMalloc *mal = (RIOMalloc *)fd->data;
	char *hex = r_hex_bin2strdup (mal->buf, mal->size);
	if (!hex) {
		return ret;
	}
	char *uri = r_str_newf ("hex://%s", hex);
	free (hex);
	if (uri) {
		free (fd->uri);
		fd->uri = uri;
	}
	return ret;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	if (!io_memory_resize (io, fd, count)) {
		return false;
	}
	if (!fd->uri) {
		return true;
	}
	if (r_str_startswith (fd->uri, "malloc://")) {
		char *uri = r_str_newf ("malloc://%"PFMT64u, count);
		if (uri) {
			free (fd->uri);
			fd->uri = uri;
		}
		return true;
	}
	if (r_str_startswith (fd->uri, "hex://")) {
		RIOMalloc *mal = (RIOMalloc *)fd->data;
		char *hex = r_hex_bin2strdup (mal->buf, mal->size);
		if (!hex) {
			return true;
		}
		char *uri = r_str_newf ("hex://%s", hex);
		free (hex);
		if (uri) {
			free (fd->uri);
			fd->uri = uri;
		}
	}
	return true;
}

RIOPlugin r_io_plugin_malloc = {
	.meta = {
		.name = "malloc",
		.desc = "Memory allocation plugin",
		.license = "LGPL3",
	},
	.uris = "malloc://,hex://,slurp://,stdin://",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.seek = io_memory_lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_malloc,
	.version = R2_VERSION
};
#endif
