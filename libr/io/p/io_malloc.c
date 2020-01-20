/* radare - LGPL - Copyright 2008-2017 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	ut8 *buf;
	ut32 size;
	ut64 offset;
} RIOMalloc;

static inline ut32 _io_malloc_sz(RIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal? mal->size: 0;
}

static inline void _io_malloc_set_sz(RIODesc *desc, ut32 sz) {
	if (!desc) {
		return;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		mal->size = sz;
	}
}

static inline ut8* _io_malloc_buf(RIODesc *desc) {
	if (!desc) {
		return NULL;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal->buf;
}


static inline ut8* _io_malloc_set_buf(RIODesc *desc, ut8* buf) {
	if (!desc) {
		return NULL;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal->buf = buf;
}

static inline ut64 _io_malloc_off(RIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal->offset;
}

static inline void _io_malloc_set_off(RIODesc *desc, ut64 off) {
	if (!desc) {
		return;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	mal->offset = off;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	if (_io_malloc_off (fd) > _io_malloc_sz (fd)) {
		return -1;
	}
	if (_io_malloc_off (fd) + count > _io_malloc_sz (fd)) {
		count -= (_io_malloc_off (fd) + count -_io_malloc_sz (fd));
	}
	if (count > 0) {
		memcpy (_io_malloc_buf (fd) + _io_malloc_off (fd), buf, count);
		_io_malloc_set_off (fd, _io_malloc_off (fd) + count);
		return count;
	}
	return -1;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	ut8 * new_buf = NULL;
	if (!fd || !fd->data || count == 0) {
		return false;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	if (_io_malloc_off (fd) > mallocsz) {
		return false;
	}
	new_buf = malloc (count);
	if (!new_buf) {
		return -1;
	}
	memcpy (new_buf, _io_malloc_buf (fd), R_MIN (count, mallocsz));
	if (count > mallocsz) {
		memset (new_buf + mallocsz, 0, count - mallocsz);
	}
	free (_io_malloc_buf (fd));
	_io_malloc_set_buf (fd, new_buf);
	_io_malloc_set_sz (fd, count);
	return true;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (!fd || !fd->data) {
		return -1;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	if (_io_malloc_off (fd) > mallocsz) {
		return -1;
	}
	if (_io_malloc_off (fd) + count >= mallocsz) {
		count = mallocsz - _io_malloc_off (fd);
	}
	memcpy (buf, _io_malloc_buf (fd) + _io_malloc_off (fd), count);
	_io_malloc_set_off (fd, _io_malloc_off (fd) + count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	ut64 r_offset = offset;
	if (!fd || !fd->data) {
		return offset;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	switch (whence) {
	case SEEK_SET:
		r_offset = (offset <= mallocsz) ? offset : mallocsz;
		break;
	case SEEK_CUR:
		r_offset = (_io_malloc_off (fd) + offset <= mallocsz ) ? _io_malloc_off (fd) + offset : mallocsz;
		break;
	case SEEK_END:
		r_offset = _io_malloc_sz (fd);
		break;
	}
	_io_malloc_set_off (fd, r_offset);
	return r_offset;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "malloc://", 9)) || (!strncmp (pathname, "hex://", 6));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (!strncmp (pathname, "hex://", 6)) {
			mal->size = strlen (pathname);
			mal->buf = calloc (1, mal->size + 1);
			if (!mal->buf) {
				free (mal);
				return NULL;
			}
			mal->offset = 0;
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
			mal->offset = 0;
			mal->buf = calloc (1, mal->size + 1);
		}
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
	.uris = "malloc://,hex://",
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
	.data = &r_io_plugin_malloc,
	.version = R2_VERSION
};
#endif
