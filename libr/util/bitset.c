/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>
#include <r_util/r_bitset.h>

static inline ut64 chunk_idx(ut64 bit) {
	return bit >> R_BITSET_CHUNK_SHIFT;
}

static inline ut32 word_idx(ut64 bit) {
	return (bit >> 6) & (R_BITSET_CHUNK_WORDS - 1);
}

static inline ut64 word_mask(ut64 bit) {
	return (ut64)1 << (bit & 63);
}

static void chunk_kvfree(HtUPKv *kv) {
	free (kv->value);
}

static size_t idxs_lower_bound(const RBitset *b, ut64 needle, bool *found) {
	size_t lo = 0;
	size_t hi = b->idxs_count;
	while (lo < hi) {
		size_t mid = lo + ((hi - lo) >> 1);
		ut64 v = b->idxs[mid];
		if (v < needle) {
			lo = mid + 1;
		} else if (v > needle) {
			hi = mid;
		} else {
			*found = true;
			return mid;
		}
	}
	*found = false;
	return lo;
}

static bool idxs_insert(RBitset *b, ut64 idx, size_t pos) {
	if (b->idxs_count == b->idxs_cap) {
		size_t ncap = b->idxs_cap ? b->idxs_cap * 2 : 8;
		ut64 *narr = realloc (b->idxs, ncap * sizeof (ut64));
		if (!narr) {
			return false;
		}
		b->idxs = narr;
		b->idxs_cap = ncap;
	}
	if (pos < b->idxs_count) {
		memmove (&b->idxs[pos + 1], &b->idxs[pos],
			(b->idxs_count - pos) * sizeof (ut64));
	}
	b->idxs[pos] = idx;
	b->idxs_count++;
	return true;
}

static void idxs_remove(RBitset *b, size_t pos) {
	if (pos + 1 < b->idxs_count) {
		memmove (&b->idxs[pos], &b->idxs[pos + 1],
			(b->idxs_count - pos - 1) * sizeof (ut64));
	}
	b->idxs_count--;
}

R_API RBitset *r_bitset_new(void) {
	RBitset *b = R_NEW0 (RBitset);
	b->chunks = ht_up_new (NULL, chunk_kvfree, NULL);
	return b;
}

R_API void r_bitset_free(RBitset *b) {
	R_RETURN_IF_FAIL (b);
	ht_up_free (b->chunks);
	free (b->idxs);
	free (b);
}

R_API void r_bitset_reset(RBitset *b) {
	R_RETURN_IF_FAIL (b);
	ht_up_free (b->chunks);
	b->chunks = ht_up_new (NULL, chunk_kvfree, NULL);
	b->idxs_count = 0;
	b->popcount = 0;
}

R_API bool r_bitset_set(RBitset *b, ut64 bit) {
	R_RETURN_VAL_IF_FAIL (b, false);
	ut64 ci = chunk_idx (bit);
	bool found = false;
	ut64 *chunk = ht_up_find (b->chunks, ci, &found);
	if (!found) {
		chunk = calloc (R_BITSET_CHUNK_WORDS, sizeof (ut64));
		if (!chunk) {
			return false;
		}
		ht_up_insert (b->chunks, ci, chunk);
		bool present = false;
		size_t pos = idxs_lower_bound (b, ci, &present);
		if (!idxs_insert (b, ci, pos)) {
			ht_up_delete (b->chunks, ci);
			return false;
		}
	}
	ut32 wi = word_idx (bit);
	ut64 mask = word_mask (bit);
	if (chunk[wi] & mask) {
		return false;
	}
	chunk[wi] |= mask;
	b->popcount++;
	return true;
}

R_API bool r_bitset_unset(RBitset *b, ut64 bit) {
	R_RETURN_VAL_IF_FAIL (b, false);
	ut64 ci = chunk_idx (bit);
	bool found = false;
	ut64 *chunk = ht_up_find (b->chunks, ci, &found);
	if (!found) {
		return false;
	}
	ut32 wi = word_idx (bit);
	ut64 mask = word_mask (bit);
	if (!(chunk[wi] & mask)) {
		return false;
	}
	chunk[wi] &= ~mask;
	b->popcount--;
	bool empty = true;
	ut32 i;
	for (i = 0; i < R_BITSET_CHUNK_WORDS; i++) {
		if (chunk[i]) {
			empty = false;
			break;
		}
	}
	if (empty) {
		bool present = false;
		size_t pos = idxs_lower_bound (b, ci, &present);
		if (present) {
			idxs_remove (b, pos);
		}
		ht_up_delete (b->chunks, ci);
	}
	return true;
}

R_API bool r_bitset_test(const RBitset *b, ut64 bit) {
	R_RETURN_VAL_IF_FAIL (b, false);
	ut64 ci = chunk_idx (bit);
	bool found = false;
	ut64 *chunk = ht_up_find (b->chunks, ci, &found);
	if (!found) {
		return false;
	}
	return (chunk[word_idx (bit)] & word_mask (bit)) != 0;
}

R_API ut64 r_bitset_count(const RBitset *b) {
	R_RETURN_VAL_IF_FAIL (b, 0);
	return b->popcount;
}

R_API ut64 r_bitset_find_next(const RBitset *b, ut64 from) {
	R_RETURN_VAL_IF_FAIL (b, UT64_MAX);
	if (b->idxs_count == 0) {
		return UT64_MAX;
	}
	ut64 ci = chunk_idx (from);
	bool present = false;
	size_t pos = idxs_lower_bound (b, ci, &present);
	ut32 start_w = present? word_idx (from): 0;
	ut64 start_bit = present? (from & 63): 0;
	for (; pos < b->idxs_count; pos++) {
		ut64 cur_ci = b->idxs[pos];
		bool found = false;
		ut64 *chunk = ht_up_find (b->chunks, cur_ci, &found);
		if (!found) {
			continue;
		}
		ut32 w = (cur_ci == ci)? start_w: 0;
		for (; w < R_BITSET_CHUNK_WORDS; w++) {
			ut64 word = chunk[w];
			if (cur_ci == ci && w == start_w && start_bit) {
				word &= ~(((ut64)1 << start_bit) - 1);
			}
			if (word) {
				ut64 base = (cur_ci << R_BITSET_CHUNK_SHIFT) + ((ut64)w << 6);
				return base + r_bits_ctz64 (word);
			}
		}
		ci = UT64_MAX;
	}
	return UT64_MAX;
}

R_API void r_bitset_foreach(const RBitset *b, RBitsetForeachCb cb, void *user) {
	R_RETURN_IF_FAIL (b && cb);
	size_t i;
	for (i = 0; i < b->idxs_count; i++) {
		ut64 ci = b->idxs[i];
		bool found = false;
		ut64 *chunk = ht_up_find (b->chunks, ci, &found);
		if (!found) {
			continue;
		}
		ut32 w;
		for (w = 0; w < R_BITSET_CHUNK_WORDS; w++) {
			ut64 word = chunk[w];
			ut64 base = (ci << R_BITSET_CHUNK_SHIFT) + ((ut64)w << 6);
			while (word) {
				ut64 bit = base + r_bits_ctz64 (word);
				if (!cb (bit, user)) {
					return;
				}
				word &= word - 1;
			}
		}
	}
}
