/* sdb - MIT - Copyright 2018-2023 - ret2libc, pancake, luc-tielen */

#include <stdint.h>
#include "sdb/ht_pu.h"
#include "sdb/heap.h"
#include "sdb/cwisstable.h"

CWISS_DECLARE_FLAT_HASHMAP_DEFAULT(HtPU_, void*, ut64);

struct HtPU_t {
	HtPU_ inner;
};

SDB_API HtPU* ht_pu_new0(void) {
	HtPU *hm = (HtPU*) sdb_gh_calloc (1, sizeof (HtPU));
	if (hm) {
		hm->inner = HtPU__new (0);
	}
	return hm;
}

SDB_API void ht_pu_free(HtPU *hm) {
	if (hm) {
		HtPU__destroy (&hm->inner);
		sdb_gh_free (hm);
	}
}

SDB_API bool ht_pu_insert(HtPU *hm, void *key, ut64 value) {
	assert (hm);

	HtPU__Entry entry = { .key = key, .val = value };
	HtPU__Insert result = HtPU__insert (&hm->inner, &entry);
	return result.inserted;
}

SDB_API bool ht_pu_update(HtPU *hm, void *key, ut64 value) {
	assert (hm);

	HtPU__Entry entry = { .key = key, .val = value };
	HtPU__Insert insert_result = HtPU__insert (&hm->inner, &entry);
	const bool should_update = !insert_result.inserted;
	if (should_update) {
		HtPU__Entry *existing_entry = HtPU__Iter_get (&insert_result.iter);
		existing_entry->val = value;
	}

	return true;
}

// Update the key of an element in the hashtable
SDB_API bool ht_pu_update_key(HtPU *hm, void *old_key, void *new_key) {
	assert (hm);

	HtPU__Iter iter = HtPU__find (&hm->inner, &old_key);
	HtPU__Entry *entry = HtPU__Iter_get (&iter);
	if (!entry) {
		return false;
	}

	// First try inserting the new key
	HtPU__Entry new_entry = { .key = new_key, .val = entry->val };
	HtPU__Insert result = HtPU__insert (&hm->inner, &new_entry);
	if (!result.inserted) {
		return false;
	}

	// Then remove entry for the old key
	HtPU__erase_at (iter);
	return true;
}

SDB_API bool ht_pu_delete(HtPU *hm, void *key) {
	assert (hm);
	return HtPU__erase (&hm->inner, &key);
}

SDB_API ut64 ht_pu_find(HtPU *hm, void *key, bool* found) {
	assert (hm);
	if (found) {
		*found = false;
	}

	HtPU__Iter iter = HtPU__find (&hm->inner, &key);
	HtPU__Entry *entry = HtPU__Iter_get (&iter);
	if (!entry) {
		return 0;
	}

	if (found) {
		*found = true;
	}
	return entry->val;
}

// Iterates over all elements in the hashtable, calling the cb function on each Kv.
// If the cb returns false, the iteration is stopped.
// cb should not modify the hashtable.
SDB_API void ht_pu_foreach(HtPU *hm, HtPUForEachCallback cb, void *user) {
	assert (hm);
	HtPU__CIter iter;
	const HtPU__Entry *entry;
	for (iter = HtPU__citer (&hm->inner); (entry = HtPU__CIter_get (&iter)) != NULL; HtPU__CIter_next (&iter)) {
		if (!cb (user, entry->key, entry->val)) {
			return;
		}
	}
}
