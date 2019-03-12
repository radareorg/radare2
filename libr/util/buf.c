/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_io.h>

typedef enum {
	R_BUFFER_FILE,
	R_BUFFER_IO,
	R_BUFFER_BYTES,
	R_BUFFER_MMAP,
	R_BUFFER_SPARSE,
} RBufferType;

#include "buf_file.c"
#include "buf_sparse.c"
#include "buf_bytes.c"
#include "buf_mmap.c"
#include "buf_io.c"

static bool buf_init(RBuffer *b, const void *user) {
	return b->methods->init? b->methods->init (b, user): true;
}

static bool buf_fini(RBuffer *b) {
	return b->methods->fini? b->methods->fini (b): true;
}

static ut64 buf_get_size(RBuffer *b) {
	return b->methods->get_size? b->methods->get_size (b): UT64_MAX;
}

static int buf_read(RBuffer *b, ut8 *buf, size_t len) {
	return b->methods->read? b->methods->read (b, buf, len): -1;
}

static int buf_write(RBuffer *b, const ut8 *buf, size_t len) {
	return b->methods->write? b->methods->write (b, buf, len): -1;
}

static int buf_seek(RBuffer *b, st64 addr, int whence) {
	return b->methods->seek? b->methods->seek (b, addr, whence): -1;
}

static bool buf_resize(RBuffer *b, ut64 newsize) {
	return b->methods->resize? b->methods->resize (b, newsize): false;
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
static int sparse_read(RList *list, ut64 addr, ut8 *buf, int len) {
	int l, covered = 0;
	RListIter *iter;
	RBufferSparse *c;
	r_list_foreach (list, iter, c) {
		if (addr < c->to && c->from < addr + len) {
			if (addr < c->from) {
				l = R_MIN (addr + len - c->from, c->size);
				memcpy (buf + c->from - addr, c->data, l);
			} else {
				l = R_MIN (c->to - addr, len);
				memcpy (buf, c->data + addr - c->from, l);
			}
			covered += l;
		}
	}
	return covered;
}

static RBufferSparse *sparse_append(RList *l, ut64 addr, const ut8 *data, int len) {
	if (l && data && len > 0) {
		RBufferSparse *s = R_NEW0 (RBufferSparse);
		if (s) {
			s->data = calloc (1, len);
			if (s->data) {
				s->from = addr;
				s->to = addr + len;
				s->size = len;
				memcpy (s->data, data, len);
				return r_list_append (l, s)? s: NULL;
			}
			free (s);
		}
	}
	return NULL;
}

//ret -1 if failed; # of bytes copied if success
static int sparse_write(RList *l, ut64 addr, const ut8 *data, int len) {
	RBufferSparse *s;
	RListIter *iter;

	r_list_foreach (l, iter, s) {
		if (addr >= s->from && addr < s->to) {
			int newlen = addr + len - s->to;
			int delta = addr - s->from;
			if (newlen > 0) {
				// must realloc
				ut8 *ndata = realloc (s->data, len + newlen);
				if (ndata) {
					s->data = ndata;
				} else {
					eprintf ("sparse write fail\n");
					return -1;
				}
			}
			memcpy (s->data + delta, data, len);
			/* write here */
			return len;
		}
	}
	if (!sparse_append (l, addr, data, len)) {
		return -1;
	}
	return len;
}

static bool sparse_limits(RList *l, ut64 *min, ut64 *max) {
	bool set = false;
	RBufferSparse *s;
	RListIter *iter;

	if (min) {
		*min = UT64_MAX;
	}
	r_list_foreach (l, iter, s) {
		if (set) {
			if (min && s->from < *min) {
				*min = s->from;
			}
			if (max && s->to > *max) {
				*max = s->to;
			}
		} else {
			set = true;
			if (min) {
				*min = s->from;
			}
			if (max) {
				*max = s->to;
			}
		}
	}
	return set;
}

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
	// TODO: implement it
	return NULL;
}

R_API RBuffer *r_buf_new_with_string(const char *msg) {
	return r_buf_new_with_bytes ((const ut8 *)msg, (ut64)strlen (msg));
}

static void buffer_sparse_free(void *a) {
	RBufferSparse *s = (RBufferSparse *)a;
	free (s->data);
	free (s);
}

R_API RBuffer *r_buf_new_sparse(ut8 Oxff) {
	// TODO: implement sparse type
	RBuffer *b = new_buffer (R_BUFFER_SPARSE, NULL);
	if (!b) {
		return NULL;
	}
	b->Oxff = Oxff;
	b->sparse = r_list_newf (buffer_sparse_free);
	return b;
}

R_API RBuffer *r_buf_new() {
	struct buf_bytes_user u = { 0 };
	u.data = NULL;
	u.length = 0;
	return new_buffer (R_BUFFER_BYTES, &u);
}

R_API const ut8 *r_buf_buffer(RBuffer *b) {
	// TODO: very important, redo this
	if (b && !b->sparse && b->fd == -1 && !b->mmap) {
		return b->buf;
	}
	r_return_val_if_fail (false, NULL);
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
	int len;
	char *tmp = r_file_slurp (file, &len);
	if (!tmp) {
		return NULL;
	}

	struct buf_bytes_user u = { 0 };
	u.data_steal = (ut8 *)tmp;
	u.length = len;
	u.steal = true;
	return new_buffer (R_BUFFER_BYTES, &u);
}

R_API bool r_buf_dump(RBuffer *b, const char *file) {
	// TODO: need to redo this
	if (!b || !file) {
		return false;
	}
	return r_file_dump (file, r_buf_get_at (b, 0, NULL), r_buf_size (b), 0);
}

R_API int r_buf_seek(RBuffer *b, st64 addr, int whence) {
	r_return_val_if_fail (b, -1);
	return buf_seek (b, addr, whence);
}

R_API bool r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length) {
	r_return_val_if_fail (b && buf, false);
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

R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, size_t length) {
	r_return_val_if_fail (b && buf, false);
	return r_buf_insert_bytes (b, 0, buf, length) >= 0;
}

R_API char *r_buf_to_string(RBuffer *b) {
	ut64 sz = r_buf_size (b);
	char *s = malloc (sz + 1);
	if (r_buf_read_at (b, 0, (ut8 *)s, sz) < 0) {
		free (s);
		return NULL;
	}
	s[sz] = '\0';
	return s;
}

R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, size_t length) {
	r_return_val_if_fail (b && buf, false);

	if (r_buf_seek (b, 0, R_BUF_END) < 0) {
		return false;
	}

	return r_buf_write (b, buf, length) >= 0;
}

R_API bool r_buf_append_nbytes(RBuffer *b, size_t length) {
	r_return_val_if_fail (b, false);
	ut8 *buf = R_NEWS0 (ut8, length);
	if (!buf) {
		return false;
	}
	bool res = r_buf_append_bytes (b, buf, length);
	free (buf);
	return res;
}

R_API int r_buf_insert_bytes(RBuffer *b, ut64 addr, const ut8 *buf, size_t length) {
	int pos, r = r_buf_seek (b, 0, R_BUF_CUR);
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
	size_t tmp_length = (size_t)r;
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
	r_return_val_if_fail (b, false);
	return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
}

R_API bool r_buf_append_ut32(RBuffer *b, ut32 n) {
	r_return_val_if_fail (b, false);
	return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
}

R_API bool r_buf_append_ut64(RBuffer *b, ut64 n) {
	r_return_val_if_fail (b, false);
	return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
}

R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a) {
	r_return_val_if_fail (b && a, false);
	// TODO: get_data from buf a and append it to b

	if (!b || b->ro) {
		return false;
	}
	if (b->fd != -1) {
		r_buf_append_bytes (b, a->buf, a->length);
		return true;
	}
	if (b->empty) {
		b->length = 0;
		b->empty = 0;
	}
	if ((b->buf = realloc (b->buf, b->length + a->length))) {
		memmove (b->buf + b->length, a->buf, a->length);
		b->length += a->length;
		return true;
	}
	return false;
}

// read a max of 8 bytes at addr, and set the read length in len
R_API ut8 *r_buf_get_at(RBuffer *b, ut64 addr, int *len) {
	r_return_val_if_fail (b, NULL);
	int r = r_buf_read_at (b, addr, b->tmp, sizeof (b->tmp));
	if (len) {
		*len = R_MAX (r, 0);
	}
	return r >= 0? b->tmp: NULL;
}

R_API int r_buf_read(RBuffer *b, ut8 *buf, size_t len) {
	return buf_read (b, buf, len);
}

R_API int r_buf_write(RBuffer *b, const ut8 *buf, size_t len) {
	return buf_write (b, buf, len);
}

R_API ut8 r_buf_read8_at (RBuffer *b, ut64 addr) {
	ut8 res;
	int r = r_buf_read_at (b, addr, &res, sizeof (res));
	return r == sizeof (res) ? res : b->Oxff;
}

static int buf_format(RBuffer *dst, RBuffer *src, const char *fmt, int n) {
	int i, res = 0;
	for (i = 0; i < n; ++i) {
		int j;
		int m = 1;
		int tsize = 2;
		bool bigendian = true;

		for (j = 0; fmt[j]; ++j) {
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
				int r;

				r = r_buf_read (src, tmp, tsize);
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

R_API int r_buf_fread(RBuffer *b, ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt, -1);
	// XXX: we assume the caller knows what he's doing
	RBuffer *dst = r_buf_new_with_pointers (buf, UT64_MAX, false);
	int res = buf_format (dst, b, fmt, n);
	r_buf_free (dst);
	return res;
}

R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt, -1);
	int r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}
	return r_buf_fread (b, buf, fmt, n);
}

R_API int r_buf_fwrite(RBuffer *b, const ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt, -1);
	// XXX: we assume the caller knows what he's doing
	RBuffer *src = r_buf_new_with_pointers (buf, UT64_MAX, false);
	int res = buf_format (b, src, fmt, n);
	r_buf_free (src);
	return res;
}

R_API int r_buf_fwrite_at(RBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n) {
	r_return_val_if_fail (b && buf && fmt, -1);
	int r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}
	return r_buf_fwrite (b, buf, fmt, n);
}

R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (b && buf, -1);
	int r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}

	return r_buf_read (b, buf, len);
}

R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len) {
	r_return_val_if_fail (b && buf, -1);
	int r = r_buf_seek (b, addr, R_BUF_SET);
	if (r < 0) {
		return r;
	}

	return r_buf_write (b, buf, len);
}

R_API bool r_buf_fini(RBuffer *b) {
	if (!b) {
		return false;
	}
	if (b->refctr > 0) {
		b->refctr--;
		return false;
	}

	return buf_fini (b);
}

R_API void r_buf_free(RBuffer *b) {
	if (r_buf_fini (b)) {
		free (b);
	}
}

R_API int r_buf_append_string(RBuffer *b, const char *str) {
	r_return_val_if_fail (b && str, false);
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
