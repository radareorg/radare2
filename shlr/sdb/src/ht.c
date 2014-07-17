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
 * Integration in r2 core api and hackit up
 *    pancake <nopcode.org>
 */

#include "ht.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

/*
 * From Knuth -- a good choice for hash/rehash values is p, p-2 where
 * p and p-2 are both prime.  These tables are sized to have an extra 10%
 * free to avoid exponential performance degradation as the hash table fills
 */

static ut32 deleted_data;

static const struct {
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
	{ 16384,	18043,		18041     },
	{ 32768,	36109,		36107     },
	{ 65536,	72091,		72089     },
	{ 131072,	144409,		144407    },
	{ 262144,	288361,		288359    },
	{ 524288,	576883,		576881    },
	{ 1048576,	1153459,	1153457   },
	{ 2097152,	2307163,	2307161   },
	{ 4194304,	4613893,	4613891   },
	{ 8388608,	9227641,	9227639   },
	{ 16777216,	18455029,	18455027  },
	{ 33554432,	36911011,	36911009  },
	{ 67108864,	73819861,	73819859  },
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
SdbHashEntry* ht_search(SdbHash *ht, ut32 hash) {
	ut32 double_hash, hash_address;
	if (ht && ht->entries) {
		hash_address = hash % ht->size;
		do {
			SdbHashEntry *entry = ht->table + hash_address;
			if (entry_is_free (entry))
				return NULL;
			if (entry_is_present (entry) && entry->hash == hash)
				return entry;
			double_hash = hash % ht->rehash;
			if (double_hash == 0)
				double_hash = 1;
			hash_address = (hash_address + double_hash) % ht->size;
		} while (hash_address != hash % ht->size);
	}
	return NULL;
}

static int rehash = 0;
static void ht_rehash(SdbHash *ht, ut32 new_size_index) {
	SdbHash old_ht = *ht;
	SdbHashEntry *e;
	if (!ht || new_size_index >= ARRAY_SIZE (hash_sizes))
		return;
	// XXX: This code is redupped! fuck't
	ht->table = calloc (hash_sizes[new_size_index].size, sizeof (*ht->table));
	if (!ht->table)
		return;
	rehash = 1;
	ht->size_index = new_size_index;
	ht->size = hash_sizes[ht->size_index].size;
	ht->rehash = hash_sizes[ht->size_index].rehash;
	ht->max_entries = hash_sizes[ht->size_index].max_entries;
	ht->entries = 0;
	ht->deleted_entries = 0;
	for (e = old_ht.table; e != old_ht.table + old_ht.size; e++) {
		if (entry_is_present (e))
			ht_insert (ht, e->hash, e->data, e->iter);
	}
	free (old_ht.table);
rehash = 0;
}

SdbHash* ht_new(SdbListFree f) {
	SdbHash *ht = R_NEW (SdbHash);
	if (!ht) return NULL;
	// TODO: use slices here
	ht->list = ls_new ();
	ht->list->free = f;
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

void ht_free(SdbHash *ht) {
	if (ht) {
		free (ht->table);
		ls_free (ht->list);
		free (ht);
	}
}

void *ht_lookup(SdbHash *ht, ut32 hash) {
	SdbHashEntry *entry;
	if (!ht || !ht->list || !ht->list->head) return NULL;
	entry = ht_search (ht, hash);
	return entry? entry->data : NULL;
}

#if 0
void ht_set(SdbHash *ht, ut32 hash, void *data) {
	SdbHashEntry *e = ht_search (ht, hash);
	if (e) {
		if (ht->list->free)
			ht->list->free (e->data);
		e->data = data;
		e->iter->data = data;
	} else ht_insert (ht, hash, data, NULL);
}
#endif

/**
 * Inserts the data with the given hash into the table.
 *
 * Note that insertion may rearrange the table on a resize or rehash,
 * so previously found hash_entries are no longer valid after this function.
 */
int ht_insert(SdbHash *ht, ut32 hash, void *data, SdbListIter *iter) {
	ut32 hash_address;
	if (!ht || !data)
		return 0;

	if (ht->entries >= ht->max_entries)
		ht_rehash (ht, ht->size_index + 1);
	else if (ht->deleted_entries + ht->entries >= ht->max_entries)
		ht_rehash (ht, ht->size_index);

	hash_address = hash % ht->size;
	do {
		SdbHashEntry *entry = ht->table + hash_address;
		ut32 double_hash;

		if (!entry_is_present (entry)) {
			if (entry_is_deleted (entry))
				ht->deleted_entries--;
			entry->hash = hash;
			entry->data = data;
			entry->iter = rehash? iter: ls_append (ht->list, data);
			ht->entries++;
			return 1;
		}

		double_hash = hash % ht->rehash;
		if (double_hash == 0)
			double_hash = 1;
		hash_address = (hash_address + double_hash) % ht->size;
	} while (hash_address != hash % ht->size);

	/* We could hit here if a required resize failed. An unchecked-malloc
	 * application could ignore this result.
	 */
	return 0;
}

void ht_delete_entry(SdbHash *ht, SdbHashEntry *entry) {
	if (!ht || !entry)
		return;
	if (!rehash && entry->iter) {
		ls_delete (ht->list, entry->iter);
		entry->iter = NULL;
	}
	entry->data = (void *) &deleted_data;
	ht->entries--;
	ht->deleted_entries++;
}
