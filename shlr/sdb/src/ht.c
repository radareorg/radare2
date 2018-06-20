/* radare2 - BSD 3 Clause License - crowell, pancake 2016 */

#include "ht.h"
#include "sdb.h"

// Sizes of the ht.
const int ht_primes_sizes[] = {
#if GROWABLE
	3, 7, 11, 17, 23, 29, 37, 47, 59, 71, 89, 107, 131,
	163, 197, 239, 293, 353, 431, 521, 631, 761, 919,
	1103, 1327, 1597, 1931, 2333, 2801, 3371, 4049, 4861,
	5839, 7013, 8419, 10103, 12143, 14591, 17519, 21023,
	25229, 30293, 36353, 43627, 52361, 62851, 75431, 90523,
	108631, 130363, 156437, 187751, 225307, 270371, 324449,
	389357, 467237, 560689, 672827, 807403, 968897, 1162687,
	1395263, 1674319, 2009191, 2411033, 2893249, 3471899,
	4166287, 4999559, 5999471, 7199369
#else
	1024,
#endif
};


// Create a new hashtable and return a pointer to it.
// size - number of buckets in the hashtable
// hashfunction - the function that does the hashing, must not be null.
// comparator - the function to check if values are equal, if NULL, just checks
// == (for storing ints).
// keydup - function to duplicate to key (eg strdup), if NULL just does strup.
// valdup - same as keydup, but for values but if NULL just assign
// pair_free - function for freeing a keyvaluepair - if NULL just does free.
// calcsize - function to calculate the size of a value. if NULL, just stores 0.
static SdbHash* internal_ht_new(ut32 size, HashFunction hashfunction,
				 ListComparator comparator, DupKey keydup,
				 DupValue valdup, HtKvFreeFunc pair_free,
				 CalcSize calcsizeK, CalcSize calcsizeV) {
	SdbHash* ht = calloc (1, sizeof (*ht));
	if (!ht) {
		return NULL;
	}
	ht->size = size;
	ht->count = 0;
	ht->prime_idx = 0;
	ht->load_factor = 1;
	ht->hashfn = hashfunction;
	ht->cmp = (ListComparator)strcmp;
	ht->dupkey = keydup? keydup: (DupKey)strdup;
	ht->dupvalue = valdup? valdup: NULL; 
	ht->table = calloc (ht->size, sizeof (SdbList*));
	ht->calcsizeK = calcsizeK? calcsizeK: (CalcSize)strlen;
	ht->calcsizeV = calcsizeV? calcsizeV: NULL;
	ht->freefn = pair_free;
	ht->deleted = ls_newf (free);
#if INSERTORDER
	ht->list = ls_newf (NULL);
#endif
	// Because we use calloc, each listptr will be NULL until used */
	return ht;
}

SDB_API bool ht_delete_internal(SdbHash* ht, const char* key, ut32* hash) {
	HtKv* kv;
	SdbListIter* iter;
	ut32 computed_hash = hash ? *hash : ht->hashfn (key);
#if USE_KEYLEN
	ut32 key_len = ht->calcsizeK ((void *)key);
#endif
	ut32 bucket = computed_hash % ht->size;
#if INSERTORDER
	ls_foreach (ht->list, iter, kv) {
#if USE_KEYLEN
		if (key_len != kv->key_len) {
			continue;
		}
#endif
		if (key == kv->key || !ht->cmp (key, kv->key)) {
			ls_delete (ht->list, iter);
			ht->count--;
			break;
		}
	}
#endif
	SdbList* list = ht->table[bucket];
	ls_foreach (list, iter, kv) {
#if USE_KEYLEN
		if (key_len != kv->key_len) {
			continue;
		}
#endif
		if (key == kv->key || !ht->cmp (key, kv->key)) {
#if EXCHANGE
			ls_split_iter (list, iter);
			ls_append (ht->deleted, iter);
			if (list->free) {
				list->free (iter->data);
			}
			iter->data = NULL;
#else
			ls_delete (list, iter);
#endif
			ht->count--;
			return true;
		}
	}
	return false;
}

SDB_API SdbHash* ht_new(DupValue valdup, HtKvFreeFunc pair_free, CalcSize calcsizeV) {
	return internal_ht_new (ht_primes_sizes[0], (HashFunction)sdb_hash, 
	  			(ListComparator)strcmp, (DupKey)strdup,
				valdup, pair_free, (CalcSize)strlen, calcsizeV);
}

SDB_API void ht_free(SdbHash* ht) {
	if (ht) {
		ut32 i;
		for (i = 0; i < ht->size; i++) {
			ls_free (ht->table[i]);
		}
		free (ht->table);
		ls_free (ht->deleted);
#if INSERTORDER
		ls_free (ht->list);
#endif
		free (ht);
	}
}

SDB_API void ht_free_deleted(SdbHash* ht) {
	if (!ls_empty (ht->deleted)) {
		ls_free (ht->deleted);
		ht->deleted = ls_newf (free);
	}
}

// Increases the size of the hashtable by 2.
#if GROWABLE
static void internal_ht_grow(SdbHash* ht) {
	SdbHash* ht2;
	SdbHash swap;
	HtKv* kv;
	SdbListIter* iter;
	ut32 i, sz = ht_primes_sizes[ht->prime_idx];
	ht2 = internal_ht_new (sz, ht->hashfn, ht->cmp, ht->dupkey,
			ht->dupvalue, (HtKvFreeFunc)ht->freefn, ht->calcsize);
	ht2->prime_idx = ht->prime_idx;
	for (i = 0; i < ht->size; i++) {
		ls_foreach (ht->table[i], iter, kv) {
			(void)ht_insert (ht2, kv->key, kv->value);
		}
	}
	// And now swap the internals.
	swap = *ht;
	*ht = *ht2;
	*ht2 = swap;
	ht_free (ht2);
}
#endif

static bool internal_ht_insert_kv(SdbHash *ht, HtKv *kv, bool update) {
	bool found = false;
	if (!ht || !kv) {
		return false;
	}
	ut32 bucket, hash = ht->hashfn (kv->key);
	if (update) {
		(void)ht_delete_internal (ht, kv->key, &hash);
	} else {
		(void)ht_find (ht, kv->key, &found);
	}
	if (update || !found) {
		bucket = hash % ht->size;
		if (!ht->table[bucket]) {
			ht->table[bucket] = ls_newf ((SdbListFree)ht->freefn);
		}
		ls_prepend (ht->table[bucket], kv);
#if INSERTORDER
		ls_append (ht->list, kv);
#endif
		ht->count++;
#if GROWABLE
		// Check if we need to grow the table.
		if (ht->count >= ht->load_factor * ht_primes_sizes[ht->prime_idx]) {
			ht->prime_idx++;
			internal_ht_grow (ht);
		}
#endif
		return true;
	}
	return false;
}

static bool internal_ht_insert(SdbHash* ht, bool update, const char* key,
				void* value) {
	if (!ht || !key || !value) {
		return false;
	}
	HtKv* kv = calloc (1, sizeof (HtKv));
	if (kv) {
		kv->key = ht->dupkey ((void *)key);
		if (ht->dupvalue) {
			kv->value = ht->dupvalue ((void *)value);
		} else {
			kv->value = (void *)value;
		}
		kv->key_len = ht->calcsizeK ((void *)kv->key);
		if (ht->calcsizeV) {
			kv->value_len = ht->calcsizeV ((void *)kv->value);
		} else {
			kv->value_len = 0;
		}
		if (!internal_ht_insert_kv (ht, kv, update)) {
			if (ht->freefn) {
				ht->freefn (kv);
			}
			return false;
		}
		return true;
	}
	return false;
}

SDB_API bool ht_insert_kv(SdbHash *ht, HtKv *kv, bool update) {
	return internal_ht_insert_kv (ht, kv, update);
}
// Inserts the key value pair key, value into the hashtable.
// Doesn't allow for "update" of the value.
SDB_API bool ht_insert(SdbHash* ht, const char* key, void* value) {
	return internal_ht_insert (ht, false, key, value);
}

// Inserts the key value pair key, value into the hashtable.
// Does allow for "update" of the value.
SDB_API bool ht_update(SdbHash* ht, const char* key, void* value) {
	return internal_ht_insert (ht, true, key, value);
}

// Returns the corresponding SdbKv entry from the key.
// If `found` is not NULL, it will be set to true if the entry was found, false
// otherwise.
SDB_API HtKv* ht_find_kv(SdbHash* ht, const char* key, bool* found) {
	if (!ht) {
		return NULL;
	}
	ut32 hash, bucket;
	SdbListIter* iter;
	HtKv* kv;
#if USE_KEYLEN
	if (!key) {
		return NULL;
	}
	ut32 key_len = ht->calcsizeK ((void *)key);
#endif
	hash = ht->hashfn (key);
	bucket = hash % ht->size;
	ls_foreach (ht->table[bucket], iter, kv) {
#if USE_KEYLEN
		if (key_len != kv->key_len) {
			continue;
		}
#endif
		bool match = !ht->cmp (key, kv->key);
		if (match) {
			if (found) {
				*found = true;
			}
			return kv;
		}
	}
	if (found) {
		*found = false;
	}
	return NULL;
}

// Looks up the corresponding value from the key.
// If `found` is not NULL, it will be set to true if the entry was found, false
// otherwise.
SDB_API void* ht_find(SdbHash* ht, const char* key, bool* found) {
	bool _found = false;
	if (!found) {
		found = &_found;
	}
	HtKv* kv = ht_find_kv (ht, key, found);
	return (kv && *found)? kv->value : NULL;
}

// Deletes a entry from the hash table from the key, if the pair exists.
SDB_API bool ht_delete(SdbHash* ht, const char* key) {
	return ht_delete_internal (ht, key, NULL);
}

SDB_API void ht_foreach(SdbHash *ht, HtForeachCallback cb, void *user) {
	if (!ht) {
		return;
	}
	ut32 i = 0;
	HtKv *kv;
	SdbListIter *iter;
	for (i = 0; i < ht->size; i++) {
		ls_foreach (ht->table[i], iter, kv) {
			if (!kv || !kv->key || !kv->value) {
				continue;
			}
			if (!cb (user, kv->key, kv->value)) {
				return;
			}
		}
	}
}
