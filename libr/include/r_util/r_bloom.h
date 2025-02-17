#ifndef R_BLOOM_H
#define R_BLOOM_H

#include <r_util.h>
#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RBloomHashFunc:
 * A hash function for the bloom filter.
 * Must support arbitrary binary data.
 * @data: pointer to data buffer.
 * @len: length of the data.
 * @seed: seed or index to differentiate among hash functions.
 *
 * Returns a 32-bit hash value.
 */
typedef uint32_t (*RBloomHashFunc)(const void * data, size_t len, uint32_t seed);

/* Opaque bloom filter structure */
typedef struct r_bloom_t RBloom;

/**
 * r_bloom_new:
 * Create a new bloom filter.
 * @m: Total number of bits.
 * @k: Number of hash functions.
 * @hash_funcs: Optional array of k hash function pointers. If NULL, the
 *   default hash function is used for all k functions.
 *
 * Returns a pointer to a new RBloom, or NULL on error.
 */
R_API RBloom * r_bloom_new(size_t m, size_t k, R_NULLABLE RBloomHashFunc * hash_funcs);
R_API void r_bloom_free(R_NULLABLE RBloom * bf);

R_API bool r_bloom_add(RBloom * bf, const void *data, int len);
R_API bool r_bloom_check(RBloom * bf, const void *data, int len);

#ifdef __cplusplus
}
#endif

#endif 
