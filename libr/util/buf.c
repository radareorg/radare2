/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_io.h>

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

static ut64 remainingBytes(ut64 limit, ut64 length, ut64 offset) {
	if (offset >= length ) {
		return 0;
	}
	return R_MIN (limit, length - offset);
}
// ret copied length if successful, -1 if failed
static int r_buf_cpy(RBuffer *b, ut64 addr, ut8 *dst, const ut8 *src, int len, int write) {
	r_return_val_if_fail (b, 0);

	if (b->empty_priv) {
		return 0;
	}

	ut64 start = addr - b->base_priv + b->offset_priv;
	ut64 effective_size = r_buf_size (b);
	int real_len = len;
	if (start - b->offset_priv + len > effective_size) {
		real_len = effective_size - start + b->offset_priv;
	}
	if (real_len < 1) {
		return 0;
	}
	if (b->iob) {
		RIOBind *iob = b->iob;
		if (b->fd_priv != -1) {
			return write
				? iob->fd_write_at (iob->io, b->fd_priv, start, src, real_len)
				: iob->fd_read_at (iob->io, b->fd_priv, start, dst, real_len);
		}
		return write
			? iob->write_at (iob->io, start, src, real_len)
			: iob->read_at (iob->io, start, dst, real_len);
	}
	if (b->fd_priv != -1) {
		if (r_sandbox_lseek (b->fd_priv, start, SEEK_SET) == -1) {
			// seek failed - print error here?
			// return 0;
		}
		if (write) {
			return r_sandbox_write (b->fd_priv, src, real_len);
		}
		memset (dst, 0, real_len);
		return r_sandbox_read (b->fd_priv, dst, real_len);
	}
	if (b->sparse_priv) {
		if (write) {
			// create new with src + len
			if (sparse_write (b->sparse_priv, start, src, real_len) < 0) {
				return -1;
			}
		} else {
			// read from sparse and write into dst
			memset (dst, b->Oxff_priv, len);
			(void)sparse_read (b->sparse_priv, start, dst, real_len);
			len = R_MIN (real_len , r_buf_size (b) - addr);
		}
		return real_len;
	}
	addr = (addr == R_BUF_CUR)? b->cur_priv: start;
	if (len < 1 || !dst || addr - b->offset_priv > effective_size) {
		return -1;
	}
	if (write) {
		dst += addr;
	} else {
		src += addr;
	}
	memmove (dst, src, real_len);
	b->cur_priv = addr + real_len;
	return real_len;
}

static int r_buf_fcpy_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n, int write) {
	ut64 len, check_len;
	int i, j, k, tsize = 2, m = 1;
	bool bigendian = true;
	r_return_val_if_fail (b && !b->empty_priv, 0);

	if ((b->iob || b->fd_priv != -1) && write) {
		eprintf ("r_buf_fcpy_at write not supported yet for r_buf_new_file\n");
		return 0;
	}
	ut64 vaddr;
	if (addr == R_BUF_CUR) {
		vaddr = addr = b->cur_priv;
	} else {
		vaddr = addr;
		addr = addr - b->base_priv + b->offset_priv;
	}
	ut64 effective_size = r_buf_size (b);
	if (addr == UT64_MAX || addr > effective_size) {
		return -1;
	}
	for (i = len = 0; i < n; i++) {
		for (j = 0; fmt[j]; j++) {
			switch (fmt[j]) {
#ifdef _MSC_VER
		case'0':case'1':case'2':case'3':case'4':case'5':case'6':case'7':case'8':case'9':
#else
			case '0' ... '9':
#endif
			if (m == 1) {
				m = r_num_get (NULL, &fmt[j]);
			}
			continue;
		case 's': tsize = 2; bigendian = false; break;
		case 'S': tsize = 2; bigendian = true; break;
		case 'i':
			tsize = 4;
			bigendian = false;
			break;
		case 'I':
			tsize = 4;
			bigendian = true;
			break;
		case 'l':
			tsize = 8;
			bigendian = false;
			break;
		case 'L': tsize = 8; bigendian = true; break;
		case 'c': tsize = 1; bigendian = false; break;
		default: return -1;
		}

		/* Avoid read/write out of bound.
		   tsize and m are not user controled, then don't
		   need to check possible overflow.
		 */
		if (!UT64_ADD (&check_len, len, tsize*m)) {
			return -1;
		}
		if (!UT64_ADD (&check_len, check_len, addr)) {
			return -1;
		}
		if (check_len > effective_size) {
			return check_len;
		}

		for (k = 0; k < m; k++) {
			ut8 _dest1[sizeof (ut64)] = { 0 };
			ut8 _dest2[sizeof (ut64)] = { 0 };
			int left1, left2;
			ut64 addr1 = len + (k * tsize);
			ut64 addr2 = vaddr + addr1;
			ut8 *src1 = NULL, *src2 = NULL;
			if (b->fd_priv == -1) {
				src1 = r_buf_get_at (b, addr1, &left1);
				src2 = r_buf_get_at (b, addr2, &left2);
			}
			if (!src1 || !src2) {
				left1 = r_buf_read_at (b, addr1, _dest1, sizeof (_dest1));
				left2 = r_buf_read_at (b, addr2, _dest2, sizeof (_dest2));
				src1 = _dest1;
				src2 = _dest2;
			}
			void *dest1 = buf + addr + addr1; // shouldn't this be an address in b ?
			void *dest2 = buf + addr1;
			ut8 *dest1_8 = (ut8 *)dest1;
			ut16 *dest1_16 = (ut16 *)dest1;
			ut32 *dest1_32 = (ut32 *)dest1;
			ut64* dest1_64 = (ut64*)dest1;
			ut8* dest2_8 = (ut8*)dest2;
			ut16* dest2_16 = (ut16*)dest2;
			ut32* dest2_32 = (ut32*)dest2;
			ut64* dest2_64 = (ut64*)dest2;
			if (write) {
				switch (tsize) {
				case 1:
					*dest1_8 = r_read_ble8 (src1);
					break;
				case 2:
					*dest1_16 = r_read_ble16 (src1, bigendian);
					break;
				case 4:
					*dest1_32 = r_read_ble32 (src1, bigendian);
					break;
				case 8:
					*dest1_64 = r_read_ble64 (src1, bigendian);
					break;
				}
			} else {
				switch (tsize) {
				case 1:
					*dest2_8 = r_read_ble8 (src2);
					break;
				case 2:
					*dest2_16 = r_read_ble16 (src2, bigendian);
					break;
				case 4:
					*dest2_32 = r_read_ble32 (src2, bigendian);
					break;
				case 8:
					*dest2_64 = r_read_ble64 (src2, bigendian);
					break;
				}
			}
		}
		len += tsize * m;
		m = 1;
		}
	}
	b->cur_priv = vaddr + len;
	return len;
}

R_API RBuffer *r_buf_new_with_io(void *iob, int fd) {
	RBuffer *b = r_buf_new ();
	if (b) {
		b->iob = iob;
		b->fd_priv = fd;
	}
	return b;
}

R_API RBuffer *r_buf_new_with_pointers(const ut8 *bytes, ut64 len) {
	RBuffer *b = r_buf_new ();
	if (b && bytes && len > 0 && len != UT64_MAX) {
		b->buf_priv = (ut8*)bytes;
		b->length_priv = len;
		b->empty_priv = false;
		b->ro_priv = true;
	}
	return b;
}

R_API RBuffer *r_buf_new_empty(ut64 len) {
	RBuffer *b = r_buf_new ();
	if (!b) {
		return NULL;
	}
	b->buf_priv = calloc (len, 1);
	if (!b->buf_priv) {
		r_buf_free (b);
		return NULL;
	}
	b->length_priv = len;
	return b;
}

R_API RBuffer *r_buf_new_with_bytes(const ut8 *bytes, ut64 len) {
	RBuffer *b = r_buf_new ();
	if (b && bytes && (len > 0 && len != UT64_MAX)) {
		r_buf_set_bytes (b, bytes, len);
	}
	return b;
}

R_API RBuffer *r_buf_new_with_string(const char *msg) {
	return r_buf_new_with_bytes ((const ut8 *)msg, (ut64)strlen (msg));
}

R_API RBuffer *r_buf_new_with_bufref(RBuffer *b) {
	RBuffer *buf = r_buf_new_with_pointers (b->buf_priv, b->length_priv);
	r_buf_ref (buf);
	return buf;
}

R_API RBuffer *r_buf_new_with_buf(RBuffer *b) {
	return r_buf_new_with_bytes (b->buf_priv, b->length_priv);
}

static void buffer_sparse_free(void *a) {
	RBufferSparse *s = (RBufferSparse *)a;
	free (s->data);
	free (s);
}

R_API RBuffer *r_buf_new_sparse(ut8 Oxff) {
	RBuffer *b = r_buf_new ();
	if (!b) {
		return NULL;
	}
	b->Oxff_priv = Oxff;
	b->sparse_priv = r_list_newf (buffer_sparse_free);
	return b;
}

R_API RBuffer *r_buf_new_slice(RBuffer *b, ut64 offset, ut64 size) {
	r_return_val_if_fail (b, NULL);
	if (b->sparse_priv) {
		eprintf ("r_buf_new_slice not supported yet for sparse buffers\n");
		return NULL;
	}
	RBuffer *buf = R_NEW0 (RBuffer);
	if (!buf) {
		return NULL;
	}
	memcpy (buf, b, sizeof (RBuffer));
	buf->parent_priv = r_buf_ref (b);
	buf->ro_priv = true;
	buf->offset_priv = offset;
	if (buf->base_priv > 0) {
		buf->base_priv += offset;
	}
	buf->limit_priv = size;
	return buf;
}

R_API RBuffer *r_buf_new() {
	RBuffer *b = R_NEW0 (RBuffer);
	if (b) {
		b->offset_priv = 0;
		b->limit_priv = UT64_MAX;
		b->fd_priv = -1;
		b->Oxff_priv = 0xff;
	}
	return b;
}

R_API const ut8 *r_buf_buffer(RBuffer *b) {
	if (b && !b->sparse_priv && b->fd_priv == -1 && !b->mmap_priv) {
		return b->buf_priv;
	}
	r_return_val_if_fail (false, NULL);
}

R_API ut64 r_buf_size(RBuffer *b) {
	r_return_val_if_fail (b, 0);
	if (b->iob) {
		RIOBind *iob = b->iob;
		return remainingBytes (b->limit_priv, iob->fd_size (iob->io, b->fd_priv), b->offset_priv);
	}
	if (b->fd_priv != -1) {
		ut64 length = r_sandbox_lseek (b->fd_priv, 0, SEEK_END);
		return remainingBytes (b->limit_priv, length, b->offset_priv);
	}
	if (b->sparse_priv) {
		ut64 max = 0LL;
		if (sparse_limits (b->sparse_priv, NULL, &max)) {
			return max; // -min
		}
		return 0LL;
	}
	return b->empty_priv? 0: remainingBytes (b->limit_priv, b->length_priv, b->offset_priv);
}

// rename to new?
R_API RBuffer *r_buf_mmap(const char *file, int perm) {
	int rw = perm & R_PERM_W? true: false;
	RBuffer *b = r_buf_new ();
	if (!b) {
		return NULL;
	}
	b->mmap_priv = r_file_mmap (file, rw, 0);
	if (b->mmap_priv) {
		b->buf_priv = b->mmap_priv->buf;
		b->length_priv = b->mmap_priv->len;
		if (!b->length_priv) {
			b->empty_priv = 1;
		}
		return b;
	}
	r_buf_free (b);
	return NULL; /* we just freed b, don't return it */
}

R_API RBuffer *r_buf_new_file(const char *file, bool newFile) {
	const int mode = 0644;
	const int perm = newFile? O_RDWR | O_CREAT: O_RDWR;
	int fd = r_sandbox_open (file, perm, mode);
	if (fd != -1) {
		RBuffer *b = r_buf_new ();
		if (!b) {
			r_sandbox_close (fd);
			return NULL;
		}
		b->fd_priv = fd;
		return b;
	}
	return NULL; /* we just freed b, don't return it */
}

// TODO: rename to new_from_file ?
R_API RBuffer *r_buf_new_slurp(const char *file) {
	int len;
	RBuffer *b = r_buf_new ();
	if (!b) {
		return NULL;
	}
	b->buf_priv = (ut8 *)r_file_slurp (file, &len);
	b->length_priv = len;
	if (b->buf_priv) {
		return b;
	}
	r_buf_free (b);
	return NULL; /* we just freed b, don't return it */
}

R_API bool r_buf_dump(RBuffer *b, const char *file) {
	if (!b || !file) {
		return false;
	}
	return r_file_dump (file, r_buf_get_at (b, 0, NULL), r_buf_size (b), 0);
}

R_API ut64 r_buf_tell(RBuffer *b) {
	return r_buf_seek (b, 0, 1);
}

R_API int r_buf_seek(RBuffer *b, st64 addr, int whence) {
	ut64 min = 0LL, max = 0LL;
	ut64 pa = addr - b->base_priv + b->offset_priv;
	if (b->fd_priv != -1) {
		if (r_sandbox_lseek (b->fd_priv, pa, whence) == -1) {
			// seek failed - print error here?
			return -1;
		}
	} else if (b->sparse_priv) {
		sparse_limits (b->sparse_priv, &min, &max);
		switch (whence) {
		case R_IO_SEEK_SET: b->cur_priv = pa; break;
		case R_IO_SEEK_CUR: b->cur_priv = b->cur_priv + addr; break;
		case R_IO_SEEK_END:
			if (sparse_limits (b->sparse_priv, NULL, &max)) {
				return max; // -min
			}
			b->cur_priv = max + addr;
			break; //b->base_priv + b->length + addr; break;
		}
	} else {
		ut64 effective_size = r_buf_size (b);
		min = b->base_priv;
		max = b->base_priv + effective_size;
		switch (whence) {
		//case 0: b->cur_priv = b->base_priv + addr; break;
		case R_IO_SEEK_SET: b->cur_priv = pa; break;
		case R_IO_SEEK_CUR: b->cur_priv = b->cur_priv + addr; break;
		case R_IO_SEEK_END: b->cur_priv = max + addr; break;
		}
	}
	/* avoid out-of-bounds */
	if (b->cur_priv < min) {
		b->cur_priv = min;
	}
	if (b->cur_priv >= max) {
		b->cur_priv = max;
	}
	return (int)b->cur_priv;
}

R_API bool r_buf_set_bits(RBuffer *b, ut64 at, const ut8 *buf, int bitoff, int count) {
	r_mem_copybits_delta (b->buf_priv, at * 8, buf, bitoff, count);
	// TODO: implement r_buf_set_bits
	// TODO: get the implementation from reg/value.c ?
	return false;
}

R_API int r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length) {
	if (length <= 0 || !buf) {
		return false;
	}
	free (b->buf_priv);
	if (!(b->buf_priv = malloc (length + 1))) {
		return false;
	}
	memmove (b->buf_priv, buf, length);
	b->buf_priv[length] = '\0';
	b->length_priv = length;
	b->empty_priv = 0;
	return true;
}

R_API int r_buf_set_bytes_steal(RBuffer *b, const ut8 *buf, ut64 length) {
	if (length <= 0 || !buf) {
		return false;
	}
	free (b->buf_priv);
	b->buf_priv = (ut8*)buf;
	b->length_priv = length;
	b->empty_priv = 0;
	return true;
}

R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, int length) {
	if ((b->buf_priv = realloc (b->buf_priv, b->length_priv + length))) {
		memmove (b->buf_priv + length, b->buf_priv, b->length_priv);
		memmove (b->buf_priv, buf, length);
		b->length_priv += length;
		b->empty_priv = 0;
		return true;
	}
	return false;
}

// TODO: R_API void r_buf_insert_bytes() // with shift
// TODO: R_API void r_buf_write_bytes() // overwrite

R_API char *r_buf_to_string(RBuffer *b) {
	char *s;
	if (!b) {
		return strdup ("");
	}
	s = malloc (b->length_priv + 1);
	if (s) {
		memmove (s, b->buf_priv, b->length_priv);
		s[b->length_priv] = 0;
	}
	return s;
}

R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, int length) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->fd_priv != -1) {
		r_sandbox_lseek (b->fd_priv, 0, SEEK_END);
		r_sandbox_write (b->fd_priv, buf, length);
		return true;
	}
	if (b->empty_priv) {
		b->length_priv = b->empty_priv = 0;
	}
	if (!(b->buf_priv = realloc (b->buf_priv, 1 + b->length_priv + length))) {
		return false;
	}
	memmove (b->buf_priv + b->length_priv, buf, length);
	b->buf_priv[b->length_priv + length] = 0;
	b->length_priv += length;
	return true;
}

R_API bool r_buf_append_nbytes(RBuffer *b, int length) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->fd_priv != -1) {
		ut8 *buf = calloc (1, length);
		if (buf) {
			r_sandbox_lseek (b->fd_priv, 0, SEEK_END);
			r_sandbox_write (b->fd_priv, buf, length);
			free (buf);
			return true;
		}
		return false;
	}
	if (b->empty_priv) {
		b->length_priv = b->empty_priv = 0;
	}
	if (!(b->buf_priv = realloc (b->buf_priv, b->length_priv + length))) {
		return false;
	}
	memset (b->buf_priv + b->length_priv, 0, length);
	b->length_priv += length;
	return true;
}

R_API bool r_buf_append_ut16(RBuffer *b, ut16 n) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->fd_priv != -1) {
		return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
	}
	if (b->empty_priv) {
		b->length_priv = b->empty_priv = 0;
	}
	if (!(b->buf_priv = realloc (b->buf_priv, b->length_priv + sizeof (n)))) {
		return false;
	}
	memmove (b->buf_priv + b->length_priv, &n, sizeof (n));
	b->length_priv += sizeof (n);
	return true;
}

R_API bool r_buf_append_ut32(RBuffer *b, ut32 n) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->empty_priv) {
		b->length_priv = b->empty_priv = 0;
	}
	if (b->fd_priv != -1) {
		return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
	}
	if (!(b->buf_priv = realloc (b->buf_priv, b->length_priv + sizeof (n)))) {
		return false;
	}
	memmove (b->buf_priv + b->length_priv, &n, sizeof (n));
	b->length_priv += sizeof (n);
	return true;
}

R_API bool r_buf_append_ut64(RBuffer *b, ut64 n) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->fd_priv != -1) {
		return r_buf_append_bytes (b, (const ut8 *)&n, sizeof (n));
	}
	if (b->empty_priv) {
		b->length_priv = b->empty_priv = 0;
	}
	if (!(b->buf_priv = realloc (b->buf_priv, b->length_priv + sizeof (n)))) {
		return false;
	}
	memmove (b->buf_priv + b->length_priv, &n, sizeof (n));
	b->length_priv += sizeof (n);
	return true;
}

R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->fd_priv != -1) {
		r_buf_append_bytes (b, a->buf_priv, a->length_priv);
		return true;
	}
	if (b->empty_priv) {
		b->length_priv = 0;
		b->empty_priv = 0;
	}
	if ((b->buf_priv = realloc (b->buf_priv, b->length_priv + a->length_priv))) {
		memmove (b->buf_priv + b->length_priv, a->buf_priv, a->length_priv);
		b->length_priv += a->length_priv;
		return true;
	}
	return false;
}

R_API bool r_buf_append_buf_slice(RBuffer *b, RBuffer *a, ut64 offset, ut64 size) {
	r_return_val_if_fail (b && b->buf_priv && a && a->buf_priv, false);
	if (offset + size >= a->length_priv) {
		return false;
	}
	if ((b->buf_priv = realloc (b->buf_priv, b->length_priv + size))) {
		memmove (b->buf_priv + b->length_priv, a->buf_priv + offset, size);
		b->length_priv += size;
		return true;
	}
	return false;
}

R_API ut8 *r_buf_get_at(RBuffer *b, ut64 addr, int *left) {
	if (b->empty_priv) {
		return NULL;
	}
	if (b->iob) {
		if (b->fd_priv != -1) {
			eprintf ("r_buf_get_at not supported for r_buf_new_file\n");
			return NULL;
		}
		static ut8 buf[8];
		r_buf_read_at (b, addr, buf, sizeof (buf));
		if (left) {
			*left = 8;
		}
		return buf;
	}
	if (addr == R_BUF_CUR) {
		addr = b->cur_priv;
	} else {
		addr = addr - b->base_priv + b->offset_priv;
	}
	ut64 effective_size = r_buf_size (b);
	if (addr == UT64_MAX || addr - b->offset_priv > effective_size) {
		return NULL;
	}
	if (left) {
		*left = effective_size - addr + b->offset_priv;
	}
	return b->buf_priv + addr;
}

R_API ut8 r_buf_read8_at(RBuffer *b, ut64 addr) {
	ut8 res;
	int r = r_buf_read_at (b, addr, &res, sizeof (res));
	return r == sizeof (res)? res: b->Oxff_priv;
}

//ret 0 if failed; ret copied length if successful
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len) {
	RIOBind *iob = b->iob;
	if (!b || !buf || len < 1) {
		return 0;
	}
	// TODO: break some tests 
	// r_return_val_if_fail (b && buf && len > 0, -1);

#if R_BUF_CUR != UT64_MAX
#error R_BUF_CUR must be UT64_MAX
#endif
	if (addr == R_BUF_CUR) {
		addr = b->cur_priv;
	}
	ut64 start = addr - b->base_priv + b->offset_priv;
	ut64 effective_size = r_buf_size (b);
	int real_len = len;
	if (start - b->offset_priv + len > effective_size) {
		real_len = effective_size - start + b->offset_priv;
	}
	if (iob) {
		if (b->fd_priv != -1) {
			return iob->fd_read_at (iob->io, b->fd_priv, start, buf, real_len);
		}
		return iob->read_at (iob->io, start, buf, real_len);
	}
	if (b->fd_priv != -1) {
		if (r_sandbox_lseek (b->fd_priv, start, SEEK_SET) == -1) {
			return 0;
		}
		return r_sandbox_read (b->fd_priv, buf, real_len);
	}
	if (!b->sparse_priv) {
		if (addr < b->base_priv || len < 1) {
			return 0;
		}
		if (real_len != len) {
			memset (buf, b->Oxff_priv, len);
			len = real_len;
			if (len < 0) {
				return 0;
			}
		}
	}
	// addr will be converted to pa inside r_buf_cpy
	return r_buf_cpy (b, addr, buf, b->buf_priv, len, false);
}

R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	return r_buf_fcpy_at (b, addr, buf, fmt, n, false);
}

//ret 0 or -1 if failed; ret copied length if success
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len) {
	r_return_val_if_fail (b && buf && len >= 0, 0);

	if (len == 0) {
		return 0;
	}

	RIOBind *iob = b->iob;
	ut64 start = addr - b->base_priv + b->offset_priv;
	ut64 effective_size = r_buf_size (b);
	int real_len = len;
	if (start - b->offset_priv + len > effective_size) {
		real_len = effective_size - start + b->offset_priv;
	}
	if (iob) {
		if (b->fd_priv != -1) {
			return iob->fd_write_at (iob->io, b->fd_priv, start, buf, real_len);
		}
		return iob->write_at (iob->io, start, buf, real_len);
	}
	if (b->fd_priv != -1) {
		ut64 newlen = start + len;
		if (r_sandbox_lseek (b->fd_priv, start, SEEK_SET) == -1) {
			return 0;
		}
		if (newlen > effective_size && !b->ro_priv) {
			b->length_priv = newlen;
#ifdef _MSC_VER
			int r = _chsize (b->fd_priv, newlen);
#else
			int r = ftruncate (b->fd_priv, newlen);
#endif
			if (r != 0) {
				eprintf ("Could not resize\n");
				return 0;
			}
		} else {
			len = real_len;
		}
		return r_sandbox_write (b->fd_priv, buf, len);
	}
	if (b->sparse_priv) {
		return (sparse_write (b->sparse_priv, addr, buf, len) < 0)? -1: len;
	}
	if (b->empty_priv) {
		if (b->ro_priv) {
			return 0;
		}
		b->empty_priv = 0;
		free (b->buf_priv);
		b->buf_priv = (ut8 *) malloc (addr + len);
	}
	return r_buf_cpy (b, addr, b->buf_priv, buf, len, true);
}

R_API int r_buf_fwrite_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	return r_buf_fcpy_at (b, addr, buf, fmt, n, true);
}

R_API bool r_buf_fini(RBuffer *b) {
	if (!b) {
		return false;
	}
	if (b->parent_priv) {
		if (b->parent_priv == b) {
			return false;
		}
		r_buf_free (b->parent_priv);
		b->parent_priv = NULL;
	}
	if (b->refctr > 0) {
		b->refctr--;
		return false;
	}
	if (!b->ro_priv) {
		if (b->fd_priv != -1) {
			r_sandbox_close (b->fd_priv);
			b->fd_priv = -1;
		}
		if (b->sparse_priv) {
			r_list_free (b->sparse_priv);
			b->sparse_priv = NULL;
		}
		if (b->mmap_priv) {
			r_file_mmap_free (b->mmap_priv);
			b->mmap_priv = NULL;
		} else {
			R_FREE (b->buf_priv);
		}
	}
	// true -> can bee free()d
	return true;
}

R_API void r_buf_free(RBuffer *b) {
	if (r_buf_fini (b)) {
		free (b);
	}
}

R_API int r_buf_append_string(RBuffer *b, const char *str) {
	return r_buf_append_bytes (b, (const ut8*)str, strlen (str));
}

R_API char *r_buf_free_to_string(RBuffer *b) {
	r_return_val_if_fail (b, NULL);
	char *p;
	if (b->mmap_priv) {
		p = r_buf_to_string (b);
	} else {
		r_buf_append_bytes (b, (const ut8*)"", 1);
		p = malloc (b->length_priv + 1);
		if (!p) {
			return NULL;
		}
		memmove (p, b->buf_priv, b->length_priv);
		p[b->length_priv] = 0;
	}
	r_buf_free (b);
	return p;
}

R_API bool r_buf_resize(RBuffer *b, ut64 newsize) {
	if (!b || b->ro_priv) {
		return false;
	}
	if (b->mmap_priv) {
		return false;
	}
	if ((!b->sparse_priv && !b->buf_priv) || newsize < 1) {
		return false;
	}
	if (b->sparse_priv) {
		ut64 last_addr = 0;
		sparse_limits (b->sparse_priv, 0, &last_addr);
		int buf_len = newsize - last_addr;
		if (buf_len > 0) {
			ut8 *buf = malloc (buf_len);
			if (buf) {
				memset (buf, b->Oxff_priv, buf_len);
				sparse_write (b->sparse_priv, last_addr, buf, buf_len);
				free (buf);
				return true;
			}
		}
		eprintf ("Invalid resize for an sparse RBuffer\n");
		return false;
	}
	ut8 *buf = calloc (newsize, 1);
	if (buf) {
		ut32 len = R_MIN (newsize, b->length_priv);
		memcpy (buf, b->buf_priv, len);
		memset (buf + len, b->Oxff_priv, newsize - len);
		/* commit */
		free (b->buf_priv);
		b->buf_priv = buf;
		b->length_priv = newsize;
		return true;
	}
	return false;
}

R_API RBuffer *r_buf_ref(RBuffer *b) {
	if (b) {
		b->refctr++;
	}
	return b;
}

R_API RList *r_buf_nonempty_list(RBuffer *b) {
	if (!b->sparse_priv) {
		return NULL;
	}
	return r_list_clone (b->sparse_priv);
}
