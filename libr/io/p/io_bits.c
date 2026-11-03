/* radare - LGPL - Copyright 2026 - pancake */

#include <r_io.h>

// R2R db/io/bits

typedef struct {
	char *path;
	ut8 *packed;
	size_t packed_size;
	ut64 size;
	ut64 offset;
	int bits;
	int unit;
	bool be;
	bool changed;
} RIOBits;

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "bits://");
}

static ut64 bits_unit_get(RIOBits *rb, ut64 index, ut8 *word) {
	const ut64 value = r_mem_get_bits (rb->packed, index * rb->bits, rb->bits, rb->be);
	r_write_ble (word, value, rb->be, rb->unit * 8);
	return value;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOBits *rb = fd->data;
	if (count < 0 || rb->offset > rb->size) {
		return -1;
	}
	const ut64 len = R_MIN ((ut64)count, rb->size - rb->offset);
	ut64 done = 0;
	while (done < len) {
		const ut64 pos = rb->offset + done;
		const int skip = pos % rb->unit;
		const ut64 chunk = R_MIN ((ut64)(rb->unit - skip), len - done);
		ut8 word[8];
		bits_unit_get (rb, pos / rb->unit, word);
		memcpy (buf + done, word + skip, chunk);
		done += chunk;
	}
	rb->offset += len;
	return (int)len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOBits *rb = fd->data;
	if (count < 0 || rb->offset > rb->size) {
		return -1;
	}
	const ut64 len = R_MIN ((ut64)count, rb->size - rb->offset);
	const ut64 mask = (rb->bits == 64)? UT64_MAX: (1ULL << rb->bits) - 1;
	ut64 done = 0;
	while (done < len) {
		const ut64 pos = rb->offset + done;
		const ut64 index = pos / rb->unit;
		const int skip = pos % rb->unit;
		const ut64 chunk = R_MIN ((ut64)(rb->unit - skip), len - done);
		ut8 word[8];
		bits_unit_get (rb, index, word);
		memcpy (word + skip, buf + done, chunk);
		const ut64 value = r_read_ble (word, rb->be, rb->unit * 8);
		if (value & ~mask) {
			R_LOG_WARN ("Truncating 0x%"PFMT64x" to %d bits", value, rb->bits);
		}
		r_mem_set_bits (rb->packed, index * rb->bits, rb->bits, value, rb->be);
		done += chunk;
	}
	rb->changed |= len > 0;
	rb->offset += len;
	return (int)len;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOBits *rb = fd->data;
	switch (whence) {
	case R_IO_SEEK_SET:
		rb->offset = R_MIN (offset, rb->size);
		break;
	case R_IO_SEEK_CUR:
		rb->offset = R_MIN (rb->offset + offset, rb->size);
		break;
	case R_IO_SEEK_END:
		rb->offset = rb->size;
		break;
	}
	return rb->offset;
}

static bool __close(RIODesc *fd) {
	RIOBits *rb = fd->data;
	if (!rb) {
		return false;
	}
	if (rb->changed && (fd->perm & R_PERM_W)) {
		if (!r_file_dump (rb->path, rb->packed, rb->packed_size, false)) {
			R_LOG_ERROR ("Cannot write %s", rb->path);
		}
	}
	free (rb->path);
	free (rb->packed);
	R_FREE (fd->data);
	return true;
}

// bits://<bits>[le|be]/<path>
static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}
	const char *spec = pathname + strlen ("bits://");
	const char *path = strchr (spec, '/');
	if (!path || !path[1]) {
		R_LOG_ERROR ("Usage: bits://<bits>[le|be]/<path>");
		return NULL;
	}
	char *end = NULL;
	const long bits = strtol (spec, &end, 10);
	const bool be = r_str_startswith (end, "be");
	if (be || r_str_startswith (end, "le")) {
		end += 2;
	}
	if (end != path || bits < 1 || bits > 64) {
		R_LOG_ERROR ("Invalid unit size in %s, expected 1 to 64 bits", pathname);
		return NULL;
	}
	path++;
	size_t size = 0;
	ut8 *packed = (ut8 *)r_file_slurp (path, &size);
	if (!packed) {
		R_LOG_ERROR ("Cannot open %s", path);
		return NULL;
	}
	RIOBits *rb = R_NEW0 (RIOBits);
	rb->path = strdup (path);
	rb->packed = packed;
	rb->packed_size = size;
	rb->bits = (int)bits;
	rb->unit = r_mem_bits_unit (rb->bits);
	rb->be = be;
	rb->size = ((ut64)size * 8 / rb->bits) * rb->unit;
	return r_io_desc_new (io, &r_io_plugin_bits, pathname, rw, mode, rb);
}

RIOPlugin r_io_plugin_bits = {
	.meta = {
		.name = "bits",
		.desc = "Unpack N-bit units of a packed stream into integer containers",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.uris = "bits://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_bits,
	.version = R2_VERSION
};
#endif
