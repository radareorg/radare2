/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_io.h>

// TODO: Optimize to use memcpy when buffers are not in range.. check buf boundaries and offsets and use memcpy or memmove

R_API RBuffer *r_buf_new_with_bytes (const ut8 *bytes, ut64 len) {
	RBuffer *b = r_buf_new ();
	if (bytes && (len > 0 && len != UT64_MAX))
		r_buf_set_bytes (b, bytes, len);
	return b;
}

R_API RBuffer *r_buf_new() {
	return R_NEW0 (RBuffer);
}

R_API const ut8 *r_buf_buffer (RBuffer *b) {
	if (b) return b->buf;
	return NULL;
}

R_API ut64 r_buf_size (RBuffer *b) {
	if (b && b->empty) return 0;
	else if (b) return b->length;
	return UT64_MAX;
}

R_API RBuffer *r_buf_mmap (const char *file, int flags) {
	int rw = flags&R_IO_WRITE ? R_TRUE : R_FALSE;
	RBuffer *b = r_buf_new ();
	if (!b) return NULL;
	b->mmap = r_file_mmap (file, rw, 0);
	if (b->mmap) {
		b->buf = b->mmap->buf;
		b->length = b->mmap->len;
		if (b->length == 0) b->empty = 1;
		return b;
	}
	r_buf_free (b);
	return NULL; /* we just freed b, don't return it */
}

R_API RBuffer *r_buf_file (const char *file) {
	RBuffer *b = r_buf_new ();
	if (!b) return NULL;
	b->buf = (ut8*)r_file_slurp (file, &b->length);
	if (b->buf) return b;
	r_buf_free (b);
	return NULL; /* we just freed b, don't return it */
}

R_API int r_buf_seek (RBuffer *b, st64 addr, int whence) {
	switch (whence) {
	case 0: b->cur = b->base + addr; break;
	case 1: b->cur = b->cur + addr; break;
	case 2: b->cur = b->base + b->length + addr; break;
	}
	/* avoid out-of-bounds */
	if (b->cur<b->base)
		b->cur = b->base;
	if ((b->cur-b->base)>b->length)
		b->cur = b->base;
	return (int)b->cur;
}

R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value) {
	// TODO: implement r_buf_set_bits
	// TODO: get the implementation from reg/value.c ?
	return R_FALSE;
}

R_API int r_buf_set_bytes(RBuffer *b, const ut8 *buf, int length) {
	if (length<=0 || !buf) return R_FALSE;
	free (b->buf);
	if (!(b->buf = malloc (length)))
		return R_FALSE;
	memmove (b->buf, buf, length);
	b->length = length;
	b->empty = 0;
	return R_TRUE;
}

R_API int r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, int length) {
	if (!(b->buf = realloc (b->buf, b->length+length)))
		return R_FALSE;
	memmove (b->buf+length, b->buf, b->length);
	memmove (b->buf, buf, length);
	b->length += length;
	b->empty = 0;
	return R_TRUE;
}

// TODO: R_API void r_buf_insert_bytes() // with shift
// TODO: R_API void r_buf_write_bytes() // overwrite

R_API char *r_buf_to_string(RBuffer *b) {
	char *s;
	if (!b) return strdup ("");
	s = malloc (b->length+1);
	memmove (s, b->buf, b->length);
	s[b->length] = 0;
	return s;
}

R_API int r_buf_append_bytes(RBuffer *b, const ut8 *buf, int length) {
	if (!b) return R_FALSE;
	if (b->empty) b->length = b->empty = 0;
	if (!(b->buf = realloc (b->buf, b->length+length))) {
		return R_FALSE;
	}
	memmove (b->buf+b->length, buf, length);
	b->length += length;
	return R_TRUE;
}

R_API int r_buf_append_nbytes(RBuffer *b, int length) {
	if (!b) return R_FALSE;
	if (b->empty) b->length = b->empty = 0;
	if (!(b->buf = realloc (b->buf, b->length+length)))
		return R_FALSE;
	memset (b->buf+b->length, 0, length);
	b->length += length;
	return R_TRUE;
}

R_API int r_buf_append_ut16(RBuffer *b, ut16 n) {
	if (!b) return R_FALSE;
	if (b->empty) b->length = b->empty = 0;
	if (!(b->buf = realloc (b->buf, b->length+sizeof (n))))
		return R_FALSE;
	memmove (b->buf+b->length, &n, sizeof (n));
	b->length += sizeof (n);
	return R_TRUE;
}

R_API int r_buf_append_ut32(RBuffer *b, ut32 n) {
	if (b->empty) b->length = b->empty = 0;
	if (!(b->buf = realloc (b->buf, b->length+sizeof (n))))
		return R_FALSE;
	memmove (b->buf+b->length, &n, sizeof (n));
	b->length += sizeof (n);
	return R_TRUE;
}

R_API int r_buf_append_ut64(RBuffer *b, ut64 n) {
	if (!b) return R_FALSE;
	if (b->empty) b->length = b->empty = 0;
	if (!(b->buf = realloc (b->buf, b->length+sizeof (n))))
		return R_FALSE;
	memmove (b->buf+b->length, &n, sizeof (n));
	b->length += sizeof (n);
	return R_TRUE;
}

R_API int r_buf_append_buf(RBuffer *b, RBuffer *a) {
	if (!b) return R_FALSE;
	if (b->empty) {
		b->length = 0;
		b->empty = 0;
	}
	if (!(b->buf = realloc (b->buf, b->length+a->length)))
		return R_FALSE;
	memmove (b->buf+b->length, a->buf, a->length);
	b->length += a->length;
	return R_TRUE;
}

static int r_buf_cpy(RBuffer *b, ut64 addr, ut8 *dst, const ut8 *src, int len, int write) {
	int end;
	if (!b || b->empty) return 0;
	addr = (addr==R_BUF_CUR)? b->cur: addr-b->base;
	if (len<1 || dst == NULL || addr > b->length)
		return -1;
 	end = (int)(addr+len);
	if (end > b->length)
		len -= end-b->length;
	if (write)
		dst += addr;
	else src += addr;
	memmove (dst, src, len);
	b->cur = addr + len;
	return len;
}

static int r_buf_fcpy_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n, int write) {
	ut64 len, check_len;
	int i, j, k, tsize, endian, m = 1;
	if (!b || b->empty) return 0;
	if (addr == R_BUF_CUR)
		addr = b->cur;
	else addr -= b->base;
	if (addr == UT64_MAX || addr > b->length)
		return -1;
	tsize = 2;
	for (i = len = 0; i < n; i++)
	for (j = 0; fmt[j]; j++) {
		switch (fmt[j]) {
		case '0'...'9':
			if (m == 1)
				m = r_num_get (NULL, &fmt[j]);
			continue;
		case 's': tsize = 2; endian = 1; break;
		case 'S': tsize = 2; endian = 0; break;
		case 'i': tsize = 4; endian = 1; break;
		case 'I': tsize = 4; endian = 0; break;
		case 'l': tsize = 8; endian = 1; break;
		case 'L': tsize = 8; endian = 0; break;
		case 'c': tsize = 1; endian = 1; break;
		default: return -1;
		}

		/* Avoid read/write out of bound.
		   tsize and m are not user controled, then don't
		   need to check possible overflow.
		 */
		if (!UT64_ADD (&check_len, len, tsize*m))
			return -1;
		if (!UT64_ADD (&check_len, check_len, addr))
			return -1;
		if (check_len > b->length) {
			return check_len;
			// return -1;
		}

		for (k = 0; k < m; k++) {
			if (write) {
				r_mem_copyendian (
				(ut8*)&buf[addr+len+(k*tsize)],
				(ut8*)&b->buf[len+(k*tsize)],
				tsize, endian);
			} else {
				r_mem_copyendian (
				(ut8*)&buf[len+(k*tsize)],
				(ut8*)&b->buf[addr+len+(k*tsize)],
				tsize, endian);
			}
		}
		len += tsize*m;
		m = 1;
	}
	b->cur = addr + len;
	return len;
}

R_API ut8 *r_buf_get_at (RBuffer *b, ut64 addr, int *left) {
	if (b->empty) return 0;
	if (addr == R_BUF_CUR)
		addr = b->cur;
	else addr -= b->base;
	if (addr == UT64_MAX || addr > b->length)
		return NULL;
	if (left)
		*left = b->length - addr;
	return b->buf+addr;
}

R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len) {
	st64 pa;
	if (!b || !buf || len<1) return 0;
#if R_BUF_CUR != UT64_MAX
#error R_BUF_CUR must be UT64_MAX
#endif
	if (addr == R_BUF_CUR)
		addr = b->cur;
	if (addr < b->base || len<1)
		return 0;
	pa = addr - b->base;
	if (pa+len > b->length) {
		memset (buf, 0xff, len);
		len = b->length - pa;
		if (len<0)
			return 0;
	}
	// must be +pa, but maybe its missused?
	//return r_buf_cpy (b, addr, buf, b->buf+pa, len, R_FALSE);
	return r_buf_cpy (b, addr, buf, b->buf, len, R_FALSE);
}

R_API int r_buf_fread_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	return r_buf_fcpy_at (b, addr, buf, fmt, n, R_FALSE);
}

R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len) {
	if (!b) return 0;
	if (b->empty) {
		b->empty = 0;
		free (b->buf);
		b->buf = (ut8 *) malloc (addr + len);
	}
	return r_buf_cpy (b, addr, b->buf, buf, len, R_TRUE);
}

R_API int r_buf_fwrite_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	return r_buf_fcpy_at (b, addr, buf, fmt, n, R_TRUE);
}

R_API void r_buf_deinit(RBuffer *b) {
	if (b->mmap) {
		r_file_mmap_free (b->mmap);
		b->mmap = NULL;
	} else free (b->buf);
}

R_API void r_buf_free(struct r_buf_t *b) {
	if (!b) return;
	r_buf_deinit (b);
	free (b);
}

R_API int r_buf_append_string (RBuffer *b, const char *str) {
	return r_buf_append_bytes (b, (const ut8*)str, strlen (str));
}

R_API char *r_buf_free_to_string (RBuffer *b) {
	char *p;
	if (!b) return NULL;
	if (b->mmap) {
		p = r_buf_to_string (b);
	} else {
		r_buf_append_bytes (b, (const ut8*)"", 1);
		p = (char *)b->buf;
	}
	free (b);
	return p;
}
