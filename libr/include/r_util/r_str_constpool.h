#ifndef R_STR_CONSTPOOL_H
#define R_STR_CONSTPOOL_H

#include <r_types.h>
#include <sdb/sdbht.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RStrConstPool is a pool of constant strings.
 * References to strings will be valid as long as the RStrConstPool is alive.
 */

typedef struct r_str_constpool_t {
	HtPP *ht;
} RStrConstPool;

R_API bool r_str_constpool_init(RStrConstPool *pool);
R_API void r_str_constpool_fini(RStrConstPool *pool);
R_API const char *r_str_constpool_get(RStrConstPool *pool, const char *str);

#ifdef __cplusplus
}
#endif

#endif //R_STR_CONSTPOOL_H
