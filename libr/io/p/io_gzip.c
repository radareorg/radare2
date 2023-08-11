/* radare - LGPL - Copyright 2008-2022 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <sys/types.h>

typedef struct {
	ut8 *buf;
	ut32 size;
	ut64 offset;
	bool has_changed;
} RIOGzip;

static inline ut32 _io_malloc_sz(RIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RIOGzip *mal = (RIOGzip*)desc->data;
	return mal? mal->size: 0;
}

static inline void _io_malloc_set_sz(RIODesc *desc, ut32 sz) {
	if (!desc) {
		return;
	}
	RIOGzip *mal = (RIOGzip*)desc->data;
	if (mal) {
		mal->size = sz;
	}
}

static inline ut8* _io_malloc_buf(RIODesc *desc) {
	if (!desc) {
		return NULL;
	}
	RIOGzip *mal = (RIOGzip*)desc->data;
	return mal->buf;
}


static inline ut8* _io_malloc_set_buf(RIODesc *desc, ut8* buf) {
	if (!desc) {
		return NULL;
	}
	RIOGzip *mal = (RIOGzip*)desc->data;
	return mal->buf = buf;
}

static inline ut64 _io_malloc_off(RIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RIOGzip *mal = (RIOGzip*)desc->data;
	return mal->offset;
}

static inline void _io_malloc_set_off(RIODesc *desc, ut64 off) {
	if (!desc) {
		return;
	}
	RIOGzip *mal = (RIOGzip*)desc->data;
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
		RIOGzip *riom = fd->data;
		riom->has_changed = true;
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
		return false;
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
	return count;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	RIOGzip *riom = fd->data;
	if (riom->has_changed) {
		R_LOG_ERROR ("TODO: Writing changes into gzipped files is not yet supported");
	}
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return true;
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

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "gzip://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		size_t len;
		ut8 *data = (ut8 *)r_file_slurp (pathname + 7, &len); //memleak here?
		if (!data) {
			return NULL;
		}
		RIOGzip *mal = R_NEW0 (RIOGzip);
		if (!mal) {
			free (data);
			return NULL;
		}
		int *size = (int*)&mal->size;
		mal->buf = r_inflate (data, (int)len, NULL, size);
		free (data);
		if (mal->buf) {
			return r_io_desc_new (io, &r_io_plugin_gzip, pathname, rw, mode, mal);
		}
		R_LOG_ERROR ("Cannot allocate %d bytes for %s", mal->size, pathname + 9);
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_gzip = {
	.meta = {
		.name = "gzip",
		.desc = "Read/write gzipped files",
		.license = "LGPL3",
	},
	.uris = "gzip://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_gzip,
	.version = R2_VERSION
};
#endif
