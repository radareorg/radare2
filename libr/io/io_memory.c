/* radare - LGPL - Copyright 2008-2022 - pancake */

#include "io_memory.h"

static inline ut32 _io_malloc_sz(RIODesc *desc) {
	r_return_val_if_fail (desc, 0);
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal? mal->size: 0;
}

static inline ut8* _io_malloc_buf(RIODesc *desc) {
	r_return_val_if_fail (desc, NULL);
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal->buf;
}

#if 0
static inline ut8* _io_malloc_set_buf(RIODesc *desc, ut8* buf) {
	if (!desc) {
		return NULL;
	}
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal->buf = buf;
}
#endif

static inline ut64 _io_malloc_off(RIODesc *desc) {
	r_return_val_if_fail (desc, 0);
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	return mal->offset;
}

static inline void _io_malloc_set_off(RIODesc *desc, ut64 off) {
	r_return_if_fail (desc);
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	mal->offset = off;
}

int io_memory_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	r_return_val_if_fail (io && fd && buf, -1);
	if (count < 0 || !fd->data) {
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
	r_return_val_if_fail (io && fd, false);
	if (count == 0) { // TODO: why cant truncate to 0 bytes
		return false;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	if (_io_malloc_off (fd) > mallocsz) {
		return false;
	}
	RIOMalloc *mal = (RIOMalloc*)fd->data;
	ut8 *new_buf = realloc (mal->buf, count);
	if (!new_buf) {
		return false;
	}
	mal->buf = new_buf;
	if (count > mal->size) {
		memset (mal->buf + mal->size, 0, count - mal->size);
	}
	mal->size = count;
	return true;
}

int io_memory_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	r_return_val_if_fail (io && fd && buf, -1);
	memset (buf, 0xff, count);
	if (!fd->data) {
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

bool io_memory_close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	RIOMalloc *riom = fd->data;
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return true;
}

ut64 io_memory_lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	r_return_val_if_fail (io && fd, offset);
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
