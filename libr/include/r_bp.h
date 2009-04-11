#ifndef _INCLUDE_LIBR_BP_H_
#define _INCLUDE_LIBR_BP_H_

#include "r_types.h"
#include "list.h"

struct r_bp_t {
	int trace;
	int nbps;
	struct list_head bps;
};


R_API int r_bp_init(struct r_bp_t *bp);
R_API struct r_bp_t *r_bp_new();
R_API struct r_bp_t *r_bp_free(struct r_bp_t *bp);
R_API int r_bp_add(struct r_bp_t *bp, u64 addr, int hw, int type);
R_API int r_bp_list(struct r_bp_t *bp, int rad);

#endif
