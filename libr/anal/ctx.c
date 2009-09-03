/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>

R_API void r_anal_ctx_init(struct r_anal_ctx_t *ctx)
{
}

R_API struct r_anal_ctx_t *r_anal_ctx_new()
{
	struct r_anal_ctx_t *ctx = MALLOC_STRUCT(struct r_anal_ctx_t);
	r_anal_ctx_init(ctx);
	return ctx;
}

R_API int r_anal_ctx_set_bytes(struct r_anal_t *anal, const ut8 *buf, int len)
{
}

R_API void r_anal_ctx_reset(struct r_anal_t *anal)
{
}

#if 0
/* getter/setter */
R_API struct r_anal_ctx_t *r_anal_ctx_get(struct r_anal_t *anal)
{
	return anal->ctx;
}

R_API void r_anal_ctx_set(struct r_anal_t *anal, struct r_anal_ctx_t *ctx)
{
	anal->ctx = ctx;
}
#endif
