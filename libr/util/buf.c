/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"

#if 0
/* TODO: the basic object lifecycle must be simplified */
struct r_class_t {
	// new/free are implicit
	.init = &r_buf_init,
	.fini = &r_buf_fini,
} r_buf_class;

#define r_buf_init(x) r_buf_class->init
#endif

R_API struct r_buf_t *r_buf_new() {
	RBuffer *b;
	
	b = R_NEW (RBuffer);
	if (b) {
		b->buf = NULL;
		b->length = 0;
		b->cur = 0;
		b->base = 0LL;
	}
	return b;
}

R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value) {
	// TODO: implement r_buf_set_bits
	// TODO: get the implementation from reg/value.c ?
	return R_FALSE;
}

R_API int r_buf_set_bytes(RBuffer *b, ut8 *buf, int length) {
	if (b->buf)
		free (b->buf);
	if (!(b->buf = malloc (length)))
		return R_FALSE;
	memcpy (b->buf, buf, length);
	b->length = length;
	return R_TRUE;
}

static int r_buf_cpy(RBuffer *b, ut64 addr, ut8 *dst, const ut8 *src, int len, int write) {
	int end;
	if (addr == R_BUF_CUR)
		addr = b->cur;
	else addr -= b->base;
	if (addr > b->length)
		return -1;
 	end = (int)(addr+len);
	if (end > b->length)
		len -= end-b->length;
	if (write)
		dst += addr;
	else src += addr;
	memcpy (dst, src, len);
	b->cur = addr + len;
	return len;
}

static int r_buf_fcpy_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n, int write) {
	int i, j, k, len, tsize, endian, m = 1;

	if (addr == R_BUF_CUR)
		addr = b->cur;
	else addr -= b->base;
	if (addr < 0 || addr > b->length)
		return -1;
	for (i = len = 0; i < n; i++)
	for (j = 0; fmt[j]; j++) {
		if (len > b->length)
			return -1;
		switch (fmt[j]) {
		case '0'...'9':
			if (m == 1)
				m = r_num_get(NULL, &fmt[j]);
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
		for (k = 0; k < m; k++) {
			if (write) r_mem_copyendian((ut8*)&buf[addr+len+k*tsize],
					(ut8*)&b->buf[len+k*tsize], tsize, endian);
			else r_mem_copyendian((ut8*)&buf[len+k*tsize],
					(ut8*)&b->buf[addr+len+k*tsize], tsize, endian);
		}
		len += m*tsize; m = 1;
	}
	b->cur = addr + len;
	return len;
}

R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len) {
	return r_buf_cpy (b, addr, buf, b->buf, len, R_FALSE);
}

R_API int r_buf_fread_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	return r_buf_fcpy_at (b, addr, buf, fmt, n, R_FALSE);
}

R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len) {
	return r_buf_cpy (b, addr, b->buf, buf, len, R_TRUE);
}

R_API int r_buf_fwrite_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	return r_buf_fcpy_at (b, addr, buf, fmt, n, R_TRUE);
}

R_API void r_buf_deinit(struct r_buf_t *b) {
	free (b->buf);
}

R_API void r_buf_free(struct r_buf_t *b) {
	r_buf_deinit (b);
	free (b);
}
