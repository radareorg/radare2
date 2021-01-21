/* radare - LGPL - Copyright 2009-2020 - ret2libc, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_io.h>

typedef enum {
	R_BUFFER_FILE,
	R_BUFFER_IO,
	R_BUFFER_BYTES,
	R_BUFFER_MMAP,
	R_BUFFER_SPARSE,
	R_BUFFER_REF,
} RBufferType;

#include "buf_file.c"
#include "buf_sparse.c"
#include "buf_bytes.c"
#include "buf_mmap.c"
#include "buf_io.c"
#include "buf_ref.c"

static bool buf_init(RBuffer *b, const void *user) {
	r_return_val_if_fail (b && b->methods, false);
	return b->methods->init? b->methods->init (b, user): true;
}

static bool buf_fini(RBuffer *b) {
	r_return_val_if_fail (b && b->methods, false);
	return b->methods->fini? b->methods->fini (b): true;
}

static ut64 buf_get_size(RBuffer *b) {
	r_return_val_if_fail (b && b->methods, UT64_MAX);
	return b->methods->get_size? b->methods->get_size (b): UT64_MAX;
}

static st64 buf_read(RBuffer *b, ut8 *buf, size_t len) {
	r_return_val_if_fail (b && b->methods, -1);
	return b->methods->read? b->methods->read (b, buf, len): -1;
}

static st64 buf_write(RBuffer *b, const ut8 *buf, size_t len) {
	r_return_val_if_fail (b && b->methods, -1);
	R_FREE (b->whole_buf);
	return b->methods->write? b->methods->write (b, buf, len): -1;
}

static st64 buf_seek(RBuffer *b, st64 addr, int whence) {
	r_return_val_if_fail (b && b->methods, -1);
	return b->methods->seek? b->methods->seek (b, addr, whence): -1;
}

static bool buf_resize(RBuffer *b, ut64 newsize) {
	r_return_val_if_fail (b && b->methods, -1);
	return b->methods->resize? b->methods->resize (b, newsize): false;
}

static ut8 *get_whole_buf(RBuffer *b, ut64 *sz) {
	r_return_val_if_fail (b && b->methods, NULL);
	if (b->methods->get_whole_buf) {
		return b->methods->get_whole_buf (b, sz);
	}
	ut64 bsz = r_buf_size (b);
	// bsz = 4096; // FAKE MINIMUM SIZE TO READ THE BIN HEADER
	if (bsz == UT64_MAX) {
		return NULL;
	}
	free (b->whole_buf);
	b->whole_buf = R_NEWS (ut8, bsz);
	if (!b->whole_buf) {
		return NULL;
	}
	r_buf_read_at (b, 0, b->whole_buf, bsz);
	if (sz) {
		*sz = bsz;
	}
	return b->whole_buf;
}

static RBuffer *new_buffer(RBufferType type, const void *user) {
	RBuffer *b = R_NEW0 (RBuffer);
	if (!b) {
		return NULL;
	}
	switch (type) {
	case R_BUFFER_BYTES:
		b->methods = &buffer_bytes_methods;
		break;
	case R_BUFFER_MMAP:
		b->methods = &buffer_mmap_methods;
		break;
	case R_BUFFER_SPARSE:
		b->methods = &buffer_sparse_methods;
		break;
	case R_BUFFER_FILE:
		b->methods = &buffer_file_methods;
		break;
	case R_BUFFER_IO:
		b->methods = &buffer_io_methods;
		break;
	case R_BUFFER_REF:
		b->methods = &buffer_ref_methods;
		break;
	default:
		r_warn_if_reached ();
		break;
	}
	if (!buf_init (b, user)) {
		free (b);
		return NULL;
	}
	return b;
}

// TODO: Optimize to use memcpy when buffers are not in range..
// check buf boundaries and offsets and use memcpy or memmove

// copied from libr/io/cache.c:r_io_cache_read
// ret # of bytes copied
R_API RBuffer *r_buf_new_with_io(void *iob, int fd) {
	r_return_val_if_fail (iob && fd >= 0, NULL);
	struct buf_io_user u = { 0 };
	u.iob = (RIOBind *)iob;
	u.fd = fd;
	return new_buffer (R_BUFFER_IO, &u);
}

R_API RBuffer *r_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal) {
	struct buf_bytes_user u = { 0 };
	u.data_steal = bytes;
	u.length = len;
	u.steal = steal;
	return new_buffer (R_BUFFER_BYTES, &u);
}

R_API RBuffer *r_buf_new_empty(ut64 len) {
	ut8 *buf = R_NEWS0 (ut8, len);
	if (!buf) {
		return NULL;
	}

	struct buf_bytes_user u = { 0 };
	u.data_steal = buf;
	u.length = len;
	u.steal = true;
	RBuffer *res = new_buffer (R_BUFFER_BYTES, &u);
	if (!res) {
		free (buf);
	}
	return res;
}

R_API RBuffer *r_buf_new_with_bytes(const ut8 *bytes, ut64 len) {
	struct buf_bytes_user u = { 0 };
	u.data = bytes;
	u.length = len;
	return new_buffer (R_BUFFER_BYTES, &u);
}

R_API RBuffer *r_buf_new_slice(RBuffer *b, ut64 offset, ut64 size) {
	struct buf_ref_user u = { 0 };
	u.parent = b;
	u.offset = offset;
	u.size = size;
	return new_buffer (R_BUFFER_REF, &u);
}

R_API RBuffer *r_buf_new_with_string(const char *msg) {
	return r_buf_new_with_bytes ((const ut8 *)msg, (ut64)strlen (msg));
}

R_API RBuffer *r_buf_new_with_buf(RBuffer *b) {
	ut64 sz = 0;
	const ut8 *tmp = r_buf_data (b, &sz);
	return r_buf_new_with_bytes (tmp, sz);
}

R_API RBuffer *r_buf_new_sparse(ut8 Oxff) {
	RBuffer *b = new_buffer (R_BUFFER_SPARSE, NULL);
	if (b) {
		b->Oxff_priv = Oxff;
	}
	return b;
}

R_API RBuffer *r_buf_new(void) {
	struct buf_bytes_user u = { 0 };
	u.data = NULL;
	u.length = 0;
	return new_buffer (R_BUFFER_BYTES, &u);
}

R_DEPRECATE R_API const ut8 *r_buf_data(RBuffer *b, ut64 *size) {
	r_return_val_if_fail (b, NULL);
	b->whole_buf = get_whole_buf (b, size);
	return b->whole_buf;
}

R_API ut64 r_buf_size(RBuffer *b) {
	r_return_val_if_fail (b, 0);
	return buf_get_size (b);
}

// rename to new?
R_API RBuffer *r_buf_new_mmap(const char *filename, int perm) {
	r_return_val_if_fail (filename, NULL);
	struct buf_mmap_user u = { 0 };
	u.filename = filename;
	u.perm = perm;
	return new_buffer (R_BUFFER_MMAP, &u);
}

R_API RBuffer *r_buf_new_file(const char *file, int perm, int mode) {
	struct buf_file_user u = { 0 };
	u.file = file;
	u.perm = perm;
	u.mode = mode;
	return new_buffer (R_BUFFER_FILE, &u);
}

// TODO: rename to new_from_file ?
R_API RBuffer *r_buf_new_slurp(const char *file) {
	size_t len;
	char *tmp = r_file_slurp (file, &len);
	if (!tmp) {
		return NULL;
	}

	struct buf_bytes_user u = { 0 };
	u.data_steal = (ut8 *)tmp;
	u.length = (ut64)len;
	u.steal = true;
	return new_buffer (R_BUFFER_BYTES, &u);
}

R_API bool r_buf_dump(RBuffer *b, const char *file) {
	// TODO: need to redo this
	if (!b || !file) {
		return false;
	}
	ut64 tmpsz = 0;
	const ut8 *tmp = r_buf_data (b, &tmpsz);
	return r_file_dump (file, tmp, tmpsz, 0);
}

R_API st64 r_buf_seek(RBuffer *b, st64 addr, int whence) {
	r_return_val_if_fail (b, -1);
	return buf_seek (b, addr, whence);
}

R_API ut64 r_buf_tell(RBuffer *b) {
	return r_buf_seek (b, 0, R_BUF_CUR);
}

R_API bool r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length) {
	r_return_val_if_fail (b && buf && !b->readonly, false);
	if (!r_buf_resize (b, 0)) {
		return false;
	}
	if (r_buf_seek (b, 0, R_BUF_SET) < 0) {
		return false;
	}
	if (!r_buf_append_bytes (b, buf, length)) {
		return false;
	}
	return r_buf_seek (b, 0, R_BUF_SET) >= 0;
}

R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, ut64 length) {
	r_return_val_if_fail (b && buf && !b->readonly, false);
	return r_buf_insert_bytes (b, 0, buf, length) >= 0;
}

R_API char *r_buf_to_string(RBuffer *b) {
	ut64 sz = r_buf_size (b);
	char *s = malloc (sz + 1);
	if (!s) {
		return NULL;
	}
	if (r_buf_read_at (b, 0, (ut8 *)s, sz) < 0) {
		free (s);
		return NULL;
	}
	s[sz] = '\0';
	return s;
}

R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, ut64 length) {
	r_return_val_if_fail (b && buf && !b->readonly, false);

	if (r_buf_seek (b, 0, R_BUF_END) < 0) {
		return false;
	}

	return r_buf_write (b, buf, length) >= 0;
}

R_API bool r_buf_append_nbytes(RBuffer *b, ut64 length) {
	r_return_val_if_fail (b && !b->readonly, false);
	ut8 *buf = R_NEWS0 (ut8, length);
	if (!buf) {
		return false;
	}
	bool res = r_buf_append_bytes (b, buf, length);
	free (buf);
	return res;
}

R_API st64 r_buf_insert_bytes(RBuffer *b, ut64 addr, const ut8 *buf, ut64 length) {
	r_return_val_if_fail (b && !b->readonly, -1);
	st64 pos, r = r_buf_seek (b, 0, R_BUF_CUR);
	if (r < 0) {
		return r;
	}
	pos = r;
	r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		goto restore_pos;
	}

	ut64 sz = r_buf_size (b);
	ut8 *tmp = R_NEWS (ut8, sz - addr);
	r = r_buf_read (b, tmp, sz - addr);
	if (r < 0) {
		goto free_tmp;
	}
	st64 tmp_length = r;
	if (!r_buf_resize (b, sz + length)) {
		goto free_tmp;
	}
	r = r_buf_seek (b, addr + length, R_BUF_SET);
	if (r < 0) {
		goto free_tmp;
	}
	r = r_buf_write (b, tmp, tmp_length);
	if (r < 0) {
		goto free_tmp;
	}
	r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		goto free_tmp;
	}
	r = r_buf_write (b, buf, length);
free_tmp:
	free (tmp);
restore_pos:
	r_buf_seek (b, pos, R_BUF_SET);
	return r;
}

R_API bool r_buf_append_ut16(RBuffer *b, ut16 n) {
	r_return_val_if_fail (b && !b->readonly, false);
	return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
}

R_API bool r_buf_append_ut32(RBuffer *b, ut32 n) {
	r_return_val_if_fail (b && !b->readonly, false);
	return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
}

R_API bool r_buf_append_ut64(RBuffer *b, ut64 n) {
	r_return_val_if_fail (b && !b->readonly, false);
	return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
}

R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a) {
	r_return_val_if_fail (b && a && !b->readonly, false);
	ut64 sz = 0;
	const ut8 *tmp = r_buf_data (a, &sz);
	return r_buf_append_bytes (b, tmp, sz);
}

R_API bool r_buf_append_buf_slice(RBuffer *b, RBuffer *a, ut64 offset, ut64 size) {
	r_return_val_if_fail (b && a && !b->readonly, false);
	ut8 *tmp = R_NEWS (ut8, size);
	bool res = false;

	if (!tmp) {
		return false;
	}
	st64 r = r_buf_read_at (a, offset, tmp, size);
	if (r < 0) {
		goto err;
	}
	res = r_buf_append_bytes (b, tmp, r);
err:
	free (tmp);
	return res;
}

// return an heap-allocated string read from the RBuffer b at address addr. The
// length depends on the first '\0' found in the buffer. If there is no '\0' in
// the buffer, there is no string, thus NULL is returned.
R_API char *r_buf_get_string(RBuffer *b, ut64 addr) {
	const int MIN_RES_SZ = 64;
	ut8 *res = R_NEWS (ut8, MIN_RES_SZ + 1);
	ut64 sz = 0;
	st64 r = r_buf_read_at (b, addr, res, MIN_RES_SZ);
	bool null_found = false;
	while (r > 0) {
		const ut8 *needle = r_mem_mem (res + sz, r, (ut8 *)"\x00", 1);
		if (needle) {
			null_found = true;
			break;
		}
		sz += r;
		addr += r;

		ut8 *restmp = realloc (res, sz + MIN_RES_SZ + 1);
		if (!restmp) {
			free (res);
			return NULL;
		}
		res = restmp;
		r = r_buf_read_at (b, addr, res + sz, MIN_RES_SZ);
	}
	if (r < 0 || !null_found) {
		free (res);
		return NULL;
	}
	return (char *)res;
}

R_API st64 r_buf_read(RBuffer *b, ut8 *buf, ut64 len) {
	r_return_val_if_fail (b && buf, -1);
	st64 r = buf_read (b, buf, len);
	if (r >= 0 && r < len) {
		memset (buf + r, b->Oxff_priv, len - r);
	}
	return r;
}

R_API st64 r_buf_write(RBuffer *b, const ut8 *buf, ut64 len) {
	r_return_val_if_fail (b && buf && !b->readonly, -1);
	return buf_write (b, buf, len);
}

R_API ut8 r_buf_read8(RBuffer *b) {
	ut8 res;
	st64 r = r_buf_read (b, &res, sizeof (res));
	return r == sizeof (res)? res: b->Oxff_priv;
}

R_API ut8 r_buf_read8_at(RBuffer *b, ut64 addr) {
	ut8 res;
	st64 r = r_buf_read_at (b, addr, &res, sizeof (res));
	return r == sizeof (res)? res: b->Oxff_priv;
}

static st64 buf_format(RBuffer *dst, RBuffer *src, const char *fmt, int n) {
	st64 res = 0;
	int i;
	for (i = 0; i < n; i++) {
		int j;
		int m = 1;
		int tsize = 2;
		bool bigendian = true;

		for (j = 0; fmt[j]; j++) {
			switch (fmt[j]) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				if (m == 1) {
					m = r_num_get (NULL, &fmt[j]);
				}
				continue;
			case 's': tsize = 2; bigendian = false; break;
			case 'S': tsize = 2; bigendian = true; break;
			case 'i': tsize = 4; bigendian = false; break;
			case 'I': tsize = 4; bigendian = true; break;
			case 'l': tsize = 8; bigendian = false; break;
			case 'L': tsize = 8; bigendian = true; break;
			case 'c': tsize = 1; bigendian = false; break;
			default: return -1;
			}

			int k;
			for (k = 0; k < m; k++) {
				ut8 tmp[sizeof (ut64)];
				ut8 d1;
				ut16 d2;
				ut32 d3;
				ut64 d4;
				st64 r = r_buf_read (src, tmp, tsize);
				if (r < tsize) {
					return -1;
				}

				switch (tsize) {
				case 1:
					d1 = r_read_ble8 (tmp);
					r = r_buf_write (dst, (ut8 *)&d1, 1);
					break;
				case 2:
					d2 = r_read_ble16 (tmp, bigendian);
					r = r_buf_write (dst, (ut8 *)&d2, 2);
					break;
				case 4:
					d3 = r_read_ble32 (tmp, bigendian);
					r = r_buf_write (dst, (ut8 *)&d3, 4);
					break;
				case 8:
					d4 = r_read_ble64 (tmp, bigendian);
					r = r_buf_write (dst, (ut8 *)&d4, 8);
					break;
				}
				if (r < 0) {
					return -1;
				}
				res += r;
			}

			m = 1;
			bigendian = true;
		}
	}
	return res;
}

R_API st64 r_buf_fread(RBuffer *b, ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt, -1);
	// XXX: we assume the caller knows what he's doing
	RBuffer *dst = r_buf_new_with_pointers (buf, UT64_MAX, false);
	st64 res = buf_format (dst, b, fmt, n);
	r_buf_free (dst);
	return res;
}

R_API st64 r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt, -1);
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	int r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}
	r = r_buf_fread (b, buf, fmt, n);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return r;
}

R_API st64 r_buf_fwrite(RBuffer *b, const ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt && !b->readonly, -1);
	// XXX: we assume the caller knows what he's doing
	RBuffer *src = r_buf_new_with_pointers (buf, UT64_MAX, false);
	st64 res = buf_format (b, src, fmt, n);
	r_buf_free (src);
	return res;
}

R_API st64 r_buf_fwrite_at(RBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt && !b->readonly, -1);
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	st64 r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}
	r = r_buf_fwrite (b, buf, fmt, n);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return r;
}

R_API st64 r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, ut64 len) {
	r_return_val_if_fail (b && buf, -1);
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	st64 r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}

	r = r_buf_read (b, buf, len);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return r;
}

R_API st64 r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, ut64 len) {
	r_return_val_if_fail (b && buf && !b->readonly, -1);
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	st64 r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}

	r = r_buf_write (b, buf, len);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return r;
}

R_API bool r_buf_fini(RBuffer *b) {
	if (!b) {
		return false;
	}
	if (b->refctr > 0) {
		b->refctr--;
		return false;
	}

	// free the whole_buf only if it was initially allocated by the buf types
	if (b->methods->get_whole_buf) {
		if (b->methods->free_whole_buf) {
			b->methods->free_whole_buf (b);
		}
	} else {
		R_FREE (b->whole_buf);
	}
	return buf_fini (b);
}

R_API void r_buf_free(RBuffer *b) {
	if (r_buf_fini (b)) {
		free (b);
	}
}

R_API st64 r_buf_append_string(RBuffer *b, const char *str) {
	r_return_val_if_fail (b && str && !b->readonly, false);
	return r_buf_append_bytes (b, (const ut8 *)str, strlen (str));
}

R_API bool r_buf_resize(RBuffer *b, ut64 newsize) {
	r_return_val_if_fail (b, false);
	return buf_resize (b, newsize);
}

R_API RBuffer *r_buf_ref(RBuffer *b) {
	if (b) {
		b->refctr++;
	}
	return b;
}

R_API RList *r_buf_nonempty_list(RBuffer *b) {
	return b->methods->nonempty_list? b->methods->nonempty_list (b): NULL;
}

R_API st64 r_buf_uleb128(RBuffer *b, ut64 *v) {
	ut8 c = 0xff;
	ut64 s = 0, sum = 0, l = 0;
	do {
		ut8 data;
		st64 r = r_buf_read (b, &data, sizeof (data));
		if (r < 1) {
			return -1;
		}
		c = data & 0xff;
		if (s < 64) {
			sum |= ((ut64) (c & 0x7f) << s);
			s += 7;
		} else {
			sum = 0;
		}
		l++;
	} while (c & 0x80);
	if (v) {
		*v = sum;
	}
	return l;
}

R_API st64 r_buf_sleb128(RBuffer *b, st64 *v) {
	st64 result = 0, offset = 0;
	ut8 value;
	do {
		st64 chunk;
		st64 r = r_buf_read (b, &value, sizeof (value));
		if (r != sizeof (value)) {
			return -1;
		}
		chunk = value & 0x7f;
		if (offset < 64) {
			result |= (chunk << offset);
			offset += 7;
		} else {
			result = 0;
		}
	} while (value & 0x80);

	if ((value & 0x40) != 0) {
		if (offset < 64) {
			result |= ~0ULL << offset;
		}
	}
	if (v) {
		*v = result;
	}
	return offset / 7;
}
