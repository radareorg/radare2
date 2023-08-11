/* radare - LGPL - Copyright 2017-2023 - condret, pancake */

#include <r_io.h>
#include <r_lib.h>

typedef struct {
	ut64 size;
	ut64 offset;
} RIONull;

static int __write(RIO* io, RIODesc* fd, const ut8* buf, int count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	RIONull* null = (RIONull*) fd->data;
	if ((null->offset + count) > null->size) {
		int ret = null->size - null->offset;
		return ret;
	}
	null->offset += count;
	return count;
}

static bool __resize(RIO* io, RIODesc* fd, ut64 count) {
	if (fd && fd->data) {
		RIONull* null = (RIONull*) fd->data;
		null->size = count;
		if (null->offset >= count) {
			null->offset = (count != 0)? count - 1: 0LL;
		}
		return true;
	}
	return false;
}

static int __read(RIO* io, RIODesc* fd, ut8* buf, int count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	RIONull* null = (RIONull*) fd->data;
	if ((null->offset + count) > null->size) {
		int ret = null->size - null->offset;
		memset (buf, 0x00, ret);
		null->offset = null->size;
		return ret;
	}
	memset (buf, 0x00, count);
	null->offset += count;
	return count;
}

static bool __close(RIODesc* fd) {
	R_FREE (fd->data);
	return true;
}

static ut64 __lseek(RIO* io, RIODesc* fd, ut64 offset, int whence) {
	RIONull* null;
	if (!fd || !fd->data) {
		return offset;
	}
	null = (RIONull*) fd->data;
	switch (whence) {
	case SEEK_SET:
		if (offset >= null->size) {
			return null->offset = null->size - 1;
		}
		return null->offset = offset;
	case SEEK_CUR:
		if ((null->offset + offset) >= null->size) {
			return null->offset = null->size - 1;
		}
		return null->offset += offset;
	case SEEK_END:
		return null->offset = null->size - 1;
	}
	return offset;
}

static bool __plugin_open(RIO* io, const char* pathname, bool many) {
	return r_str_startswith (pathname, "null://");
}

static RIODesc* __open(RIO* io, const char* pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		if (r_str_startswith (pathname, "null://")) {
			RIONull *null = R_NEW0 (RIONull);
			if (null) {
				null->size = r_num_math (NULL, pathname + 7) + 1;
				if (null->size > ST32_MAX) {
					R_LOG_ERROR ("Large null allocation is not valid");
					return NULL;
				}
				null->offset = 0LL;
				return r_io_desc_new (io, &r_io_plugin_null, pathname, rw & R_PERM_RWX, mode, null);
			}
		}
	}
	return NULL;
}

RIOPlugin r_io_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "Null plugin",
		.license = "LGPL3",
	},
	.uris = "null://",
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
	.data = &r_io_plugin_null,
	.version = R2_VERSION
};
#endif
