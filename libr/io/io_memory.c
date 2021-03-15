/* radare - LGPL - Copyright 2008-2020 - pancake */

#include "io_memory.h"

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

int io_memory_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
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

bool io_memory_resize(RIO *io, RIODesc *fd, ut64 count) {
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

int io_memory_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
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

int io_memory_close(RIODesc *fd) {
	RIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return 0;
}

ut64 io_memory_lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
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
