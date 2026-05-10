/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_BITSET_H
#define R_BITSET_H

#include <r_types.h>
#include <sdb/ht_up.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sparse, unbounded bitmap. Stores bits in 4096-bit chunks (64 ut64 words),
 * allocated on demand and freed when emptied. Cheap when bits are clustered;
 * for very sparse, near-random keys, use SetU instead. */

#define R_BITSET_CHUNK_BITS  4096
#define R_BITSET_CHUNK_WORDS 64
#define R_BITSET_CHUNK_SHIFT 12
#define R_BITSET_CHUNK_MASK  0xfff

typedef struct r_bitset_t {
	HtUP *chunks;       // chunk_index (bit >> 12) -> ut64[64]
	ut64 *idxs;         // sorted chunk indices, for ordered iteration
	size_t idxs_count;
	size_t idxs_cap;
	ut64 popcount;      // cached number of set bits
} RBitset;

typedef bool (*RBitsetForeachCb)(ut64 bit, void *user);

R_API RBitset *r_bitset_new(void);
R_API void r_bitset_free(RBitset *b);
/* set bit; returns true if it was newly set */
R_API bool r_bitset_set(RBitset *b, ut64 bit);
/* unset bit; returns true if it was previously set */
R_API bool r_bitset_unset(RBitset *b, ut64 bit);
R_API bool r_bitset_test(const RBitset *b, ut64 bit);
R_API ut64 r_bitset_count(const RBitset *b);
R_API void r_bitset_reset(RBitset *b);
/* return the next set bit at or after `from`, or UT64_MAX if none */
R_API ut64 r_bitset_find_next(const RBitset *b, ut64 from);
/* iterate set bits in ascending order; cb returns false to stop */
R_API void r_bitset_foreach(const RBitset *b, RBitsetForeachCb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif
