/*
 * Copyright © 2009 Intel Corporation
 * Copyright © 1988-2004 Keith Packard and Bart Massey.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Except as contained in this notice, the names of the authors
 * or their institutions shall not be used in advertising or
 * otherwise to promote the sale, use or other dealings in this
 * Software without prior written authorization from the
 * authors.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *    Keith Packard <keithp@keithp.com>
 * Integration in r2 core api
 *    pancake <nopcode.org>
 */

#include <r_util.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

/*
 * From Knuth -- a good choice for hash/rehash values is p, p-2 where
 * p and p-2 are both prime.  These tables are sized to have an extra 10%
 * free to avoid exponential performance degradation as the hash table fills
 */
#if HT64
#define utH ut64
#define ht_(name) r_hashtable64_##name 
#define RHT RHashTable64
#define RHTE RHashTable64Entry
#else
#define utH ut32
#define ht_(name) r_hashtable_##name 
#define RHT RHashTable
#define RHTE RHashTableEntry
#endif

//static const utH deleted_data;
// HACK :D .. but.. use magic instead?
#define deleted_data hash_sizes

static const struct {
// XXX: this can be ut32 ...
   ut32 max_entries, size, rehash;
} hash_sizes[] = {
    { 2,		5,		3	  },
    { 4,		7,		5	  },
    { 8,		13,		11	  },
    { 16,		19,		17	  },
    { 32,		43,		41        },
    { 64,		73,		71        },
    { 128,		151,		149       },
    { 256,		283,		281       },
    { 512,		571,		569       },
    { 1024,		1153,		1151      },
    { 2048,		2269,		2267      },
    { 4096,		4519,		4517      },
    { 8192,		9013,		9011      },
    { 16384,		18043,		18041     },
    { 32768,		36109,		36107     },
    { 65536,		72091,		72089     },
    { 131072,		144409,		144407    },
    { 262144,		288361,		288359    },
    { 524288,		576883,		576881    },
    { 1048576,		1153459,	1153457   },
    { 2097152,		2307163,	2307161   },
    { 4194304,		4613893,	4613891   },
    { 8388608,		9227641,	9227639   },
    { 16777216,		18455029,	18455027  },
    { 33554432,		36911011,	36911009  },
    { 67108864,		73819861,	73819859  },
    { 134217728,	147639589,	147639587 },
    { 268435456,	295279081,	295279079 },
    { 536870912,	590559793,	590559791 },
    { 1073741824,	1181116273,	1181116271},
    { 2147483648ul,	2362232233ul,	2362232231ul}
};

#define entry_is_free(x) (!x || !x->data)
#define entry_is_deleted(x) x->data==&deleted_data
#define entry_is_present(x) (x->data && x->data != &deleted_data)

/**
 * Finds a hash table entry with the given key and hash of that key.
 *
 * Returns NULL if no entry is found.  Note that the data pointer may be
 * modified by the user.
 */
static RHTE* ht_(search)(RHT *ht, utH hash) {
	utH double_hash, hash_address;
	if (ht == NULL)
		return NULL;
	hash_address = hash % ht->size;
	do {
		RHTE *entry = ht->table + hash_address;
		if (entry_is_free (entry))
			return NULL;
		if (entry_is_present (entry) && entry->hash == hash)
			return entry;
		double_hash = hash % ht->rehash;
		if (double_hash == 0)
			double_hash = 1;
		hash_address = (hash_address + double_hash) % ht->size;
	} while (hash_address != hash % ht->size);
	return NULL;
}

static void ht_(rehash)(RHT *ht, int new_size_index) {
	RHT old_ht = *ht;
	RHTE *e;
	if (new_size_index >= ARRAY_SIZE (hash_sizes))
		return;
	// XXX: This code is redupped! fuck't
	ht->table = calloc (hash_sizes[new_size_index].size, sizeof (*ht->table));
	if (!ht->table)
		return;
	ht->size_index = new_size_index;
	ht->size = hash_sizes[ht->size_index].size;
	ht->rehash = hash_sizes[ht->size_index].rehash;
	ht->max_entries = hash_sizes[ht->size_index].max_entries;
	ht->entries = 0;
	ht->deleted_entries = 0;
	for (e = old_ht.table; e != old_ht.table + old_ht.size; e++) {
		if (entry_is_present (e))
			ht_(insert) (ht, e->hash, e->data);
	}
	free (old_ht.table);
}

R_API RHT* ht_(new)(void) {
	RHT *ht = R_NEW (RHT);
	if (!ht) return NULL;
	// TODO: use slices here
	ht->size = hash_sizes[0].size;
	ht->table = calloc (ht->size, sizeof (*ht->table));
	if (!ht->table) {
		free (ht);
		return NULL;
	}
	ht->size_index = 0;
	ht->entries = 0;
	ht->deleted_entries = 0;
	ht->rehash = hash_sizes[ht->size_index].rehash;
	ht->max_entries = hash_sizes[ht->size_index].max_entries;
	return ht;
}

R_API void ht_(free)(RHT *ht) {
	if (ht) {
		free (ht->table);
		free (ht);
	}
}

R_API void *ht_(lookup)(RHT *ht, utH hash) {
	RHTE *entry = ht_(search) (ht, hash);
	return entry? entry->data : NULL;
}

/**
 * Inserts the data with the given hash into the table.
 *
 * Note that insertion may rearrange the table on a resize or rehash,
 * so previously found hash_entries are no longer valid after this function.
 */
R_API boolt ht_(insert) (RHT *ht, utH hash, void *data) {
	utH hash_address;

	if (ht->entries >= ht->max_entries)
		ht_(rehash) (ht, ht->size_index + 1);
	else if (ht->deleted_entries + ht->entries >= ht->max_entries)
		ht_(rehash) (ht, ht->size_index);

	hash_address = hash % ht->size;
	do {
		RHTE *entry = ht->table + hash_address;
		utH double_hash;

		if (!entry_is_present (entry)) {
			if (entry_is_deleted (entry))
				ht->deleted_entries--;
			entry->hash = hash;
			entry->data = data;
			ht->entries++;
			return R_TRUE;
		}
		double_hash = hash % ht->rehash;
		if (double_hash == 0)
			double_hash = 1;
		hash_address = (hash_address + double_hash) % ht->size;
	} while (hash_address != hash % ht->size);

	/* We could hit here if a required resize failed. An unchecked-malloc
	 * application could ignore this result.
	 */
	return R_FALSE;
}

R_API void ht_(remove) (RHT *ht, utH hash) {
	RHTE *entry = ht_(search) (ht, hash);
	if (entry) {
		entry->data = (void *) &deleted_data;
		ht->entries--;
		ht->deleted_entries++;
	}
}

#if TEST
int main () {
	const char *str;
	int ret;
	RHT *ht = ht_(new) ();
#define HASH 268453705

	ret = ht_(insert) (ht, HASH, "patata");
	if (!ret)
		printf ("Cannot reinsert !!1\n");

	str = ht_(lookup) (ht, HASH);
	if (str) printf ("String is (%s)\n", str);
	else printf ("Cannot find string\n");

	ht_(remove) (ht, HASH);

	str = ht_(lookup) (ht, HASH);
	if (str) printf ("String is (%s)\n", str);
	else printf("Cannot find string which is ok :)\n");

	ht_(search) (ht, HASH);
	ht_(free) (ht);
}
#endif
