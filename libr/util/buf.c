/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

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

R_API struct r_buf_t *r_buf_init(struct r_buf_t *b)
{
	if (b) {
		b->length = 0;
		b->base = 0LL;
		b->buf = NULL;
	}
	return b;
}

R_API struct r_buf_t *r_buf_new()
{
	struct r_buf_t *b = MALLOC_STRUCT(struct r_buf_t);
	return r_buf_init(b);
}

R_API int r_buf_set_bits(struct r_buf_t *b, int bitoff, int bitsize, ut64 value)
{
	// TODO: implement r_buf_set_bits
	// TODO: get the implementation from reg/value.c ?
}

R_API int r_buf_set_bytes(struct r_buf_t *b, ut8 *buf, int length)
{
	free(b->buf);
	b->buf = malloc(length);
	if (b->buf == NULL)
		return R_FALSE;
	memcpy(b->buf, buf, length);
	b->length = length;
	return R_TRUE;
}

static int r_buf_memcpy(struct r_buf_t *b, ut64 addr, ut8 *dst, ut8 *src, int len) {
	int end;
	addr -= b->base;
	if (addr > b->length)
		return -1;
 	end = (int)(addr+len);
	if (end > b->length)
		len -= end-b->length;
	memcpy(dst, src, len);
	return len;
}

R_API int r_buf_read_at(struct r_buf_t *b, ut64 addr, ut8 *buf, int len)
{
	return r_buf_memcpy(b, addr, buf, b->buf, len);
}

R_API int r_buf_write_at(struct r_buf_t *b, ut64 addr, const ut8 *buf, int len)
{
	return r_buf_memcpy(b, addr, b->buf, buf, len);
}

R_API void r_buf_deinit(struct r_buf_t *b)
{
	free(b->buf);
}

R_API void r_buf_free(struct r_buf_t *b)
{
	r_buf_deinit(b);
	free(b);
}
