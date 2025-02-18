#ifndef R_BLOOM_H
#define R_BLOOM_H

#include "r_util/r_assert.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ut32 (*RBloomHashFunc)(const void * data, size_t len, uint32_t seed);

typedef struct r_bloom_t RBloom;

R_API RBloom *r_bloom_new(size_t m, size_t k, R_NULLABLE RBloomHashFunc * hash_funcs);
R_API void r_bloom_free(R_NULLABLE RBloom * bf);

R_API bool r_bloom_init(RBloom *bf, size_t m, size_t k, RBloomHashFunc * hash_funcs);
R_API void r_bloom_fini(R_NONNULL RBloom *bf);

R_API bool r_bloom_add(RBloom * bf, const void *data, size_t len);
R_API bool r_bloom_check(RBloom * bf, const void *data, size_t len);
R_API void r_bloom_reset(RBloom * bf);

#ifdef __cplusplus
}
#endif

#endif
