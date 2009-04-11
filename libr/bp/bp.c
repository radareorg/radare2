/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_bp.h>

R_API int r_bp_init(struct r_bp_t *bp)
{
	return R_TRUE;
}

R_API struct r_bp_t *r_bp_new()
{
	struct r_bp_t *bp = MALLOC_STRUCT(struct r_bp_t);
	r_bp_init(bp);
	return bp;
}

R_API struct r_bp_t *r_bp_free(struct r_bp_t *bp)
{
	free(bp);
	return NULL;
}

R_API int r_bp_add(struct r_bp_t *bp, u64 addr, int hw, int type)
{
	return R_TRUE;
}

R_API int r_bp_list(struct r_bp_t *bp, int rad)
{
	return 0;
}
