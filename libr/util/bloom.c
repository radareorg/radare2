/* radare - MIT - Copyright 2025 - pancake */

#include <r_util/r_bloom.h>

typedef struct r_bloom_t {
	size_t m; // number of bits
	size_t k; // number of hash functions
	ut8 *bit_array; // bit vector
	size_t array_size; // in bytes (m + 7) / 8
	RBloomHashFunc *hash_funcs;
} RBloom;

#define BF_BIT_SET(arr, i)   ((arr)[(i)/8] |= (1 << ((i) % 8)))
#define BF_BIT_CHECK(arr, i) ((arr)[(i)/8] & (1 << ((i) % 8)))

// A simple djb2-variant hash function that supports binary data
static ut32 default_bloom_hash(const void *data, size_t len, ut32 seed) {
	const ut8 *ptr = (const ut8*) data;
	ut32 hash = 5381 ^ seed;
	size_t i;
	for (i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + ptr[i]; /* hash * 33 + c */
	}
	return hash;
}

R_API R_NULLABLE RBloom *r_bloom_new(size_t m, size_t k, RBloomHashFunc * hash_funcs) {
	RBloom * bf = R_NEW (RBloom);
	bf->m = m;
	bf->k = k;
	bf->array_size = (m + 7) / 8;
	bf->bit_array = (ut8*) calloc (bf->array_size, sizeof (ut8));
	if (! bf->bit_array) {
		free (bf);
		return NULL;
	}
	bf->hash_funcs = (RBloomHashFunc *) malloc (k * sizeof (RBloomHashFunc));
	if (! bf->hash_funcs) {
		free (bf->bit_array);
		free (bf);
		return NULL;
	}
	if (hash_funcs) {
		memcpy (bf->hash_funcs, hash_funcs, k * sizeof (RBloomHashFunc));
	} else {
		size_t i;
		for (i = 0; i < k; i++) {
			bf->hash_funcs[i] = default_bloom_hash;
		}
	}
	return bf;
}

R_API void r_bloom_free(RBloom *bf) {
	if (bf) {
		free (bf->bit_array);
		free (bf->hash_funcs);
		free (bf);
	}
}

R_API bool r_bloom_add(RBloom *bf, const void * data, size_t len) {
	R_RETURN_VAL_IF_FAIL (bf && data, -1);
	size_t i;
	for (i = 0; i < bf->k; i++) {
		ut32 hash = bf->hash_funcs[i] (data, len, (ut32) i);
		size_t index = hash % bf->m;
		BF_BIT_SET (bf->bit_array, index);
	}
	return 0;
}

R_API bool r_bloom_check(RBloom *bf, const void * data, size_t len) {
	R_RETURN_VAL_IF_FAIL (bf && data, -1);
	size_t i;
	for (i = 0; i < bf->k; i++) {
		ut32 hash = bf->hash_funcs[i] (data, len, (ut32) i);
		size_t index = hash % bf->m;
		if (! BF_BIT_CHECK (bf->bit_array, index)) {
			return false;
		}
	}
	return true;
}
