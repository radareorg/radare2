/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_FLAG_PRIV_H
#define R2_FLAG_PRIV_H

#include "r_flag.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_flag_store_shadow_t RFlagStoreShadow;

// Internal cross-library ABI: declarations intentionally stay out of r_flag.h.
R_API RFlagStoreShadow *r_flag_store_shadow_prepare(const RFlag *flags);
R_API const RFlagItem *r_flag_store_shadow_get_exact(RFlagStoreShadow *shadow, const char *name);
R_API bool r_flag_store_shadow_set_exact(RFlagStoreShadow *shadow, const char *name, ut64 addr, ut32 size, const RSpace *space);
R_API bool r_flag_store_shadow_del_exact(RFlagStoreShadow *shadow, const char *name);
R_API void r_flag_store_shadow_swap(RFlag *flags, RFlagStoreShadow *shadow);
R_API void r_flag_store_shadow_free(RFlagStoreShadow *shadow);

#ifdef __cplusplus
}
#endif

#endif
