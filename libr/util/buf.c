/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"

R_API struct r_buf_t *r_buf_init(struct r_buf_t *b)
{
	b->length = 0;
	b->base = 0LL;
	b->buf = NULL;
	return b;
}

R_API struct r_buf_t *r_buf_new()
{
	struct r_buf_t *b = MALLOC_STRUCT(struct r_buf_t);
	return r_buf_init(b);
}

R_API void r_buf_set_bytes(struct r_buf_t *b, ut8 *buf, int length)
{
	free(b->buf);
	b->buf = malloc(length);
	memcpy(b->buf, buf, length);
	b->length = length;
}

static int r_buf_memcpy(struct r_buf_t *b, ut64 addr, ut8 *dst, ut8 *src, int len)
{
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

R_API int r_buf_write_at(struct r_buf_t *b, ut64 addr, ut8 *buf, int len)
{
	return r_buf_memcpy(b, addr, b->buf, buf, len);
}

R_API void r_buf_free(struct r_buf_t *b)
{
	free(b->buf);
	free(b);
}
