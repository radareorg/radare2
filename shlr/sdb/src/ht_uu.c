/* sdb - MIT - Copyright 2018-2023 - ret2libc, pancake, luc-tielen */

#include <stdint.h>
#include "sdb/ht_uu.h"
#include "sdb/heap.h"
#include "sdb/cwisstable.h"

typedef uint64_t ut64;

CWISS_DECLARE_FLAT_HASHMAP_DEFAULT(HtUU_, ut64, ut64);

struct HtUU_t {
	HtUU_ inner;
};

SDB_API HtUU* ht_uu_new0(void) {
	HtUU *hm = (HtUU*) sdb_gh_calloc (1, sizeof (HtUU));
	if (hm) {
		hm->inner = HtUU__new (0);
	}
	return hm;
}

SDB_API void ht_uu_free(HtUU *hm) {
	if (hm) {
		HtUU__destroy (&hm->inner);
		sdb_gh_free (hm);
	}
}

SDB_API bool ht_uu_insert(HtUU *hm, const ut64 key, ut64 value) {
	assert (hm);

	HtUU__Entry entry = { .key = key, .val = value };
	HtUU__Insert result = HtUU__insert (&hm->inner, &entry);
	return result.inserted;
}

SDB_API bool ht_uu_update(HtUU *hm, const ut64 key, ut64 value) {
	assert (hm);

	HtUU__Entry entry = { .key = key, .val = value };
	HtUU__Insert insert_result = HtUU__insert (&hm->inner, &entry);
	const bool should_update = !insert_result.inserted;
	if (should_update) {
		HtUU__Entry *existing_entry = HtUU__Iter_get (&insert_result.iter);
		existing_entry->val = value;
	}

	return true;
}

// Update the key of an element in the hashtable
SDB_API bool ht_uu_update_key(HtUU *hm, const ut64 old_key, const ut64 new_key) {
	assert (hm);

	HtUU__Iter iter = HtUU__find (&hm->inner, &old_key);
	HtUU__Entry *entry = HtUU__Iter_get (&iter);
	if (!entry) {
		return false;
	}

	// First try inserting the new key
	HtUU__Entry new_entry = { .key = new_key, .val = entry->val };
	HtUU__Insert result = HtUU__insert (&hm->inner, &new_entry);
	if (!result.inserted) {
		return false;
	}

	// Then remove entry for the old key
	HtUU__erase_at (iter);
	return true;
}

SDB_API bool ht_uu_delete(HtUU *hm, const ut64 key) {
	assert (hm);
	return HtUU__erase (&hm->inner, &key);
}

SDB_API ut64 ht_uu_find(HtUU *hm, const ut64 key, bool* found) {
	assert (hm);
	if (found) {
		*found = false;
	}

	HtUU__Iter iter = HtUU__find (&hm->inner, &key);
	HtUU__Entry *entry = HtUU__Iter_get (&iter);
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
SDB_API void ht_uu_foreach(HtUU *hm, HtUUForEachCallback cb, void *user) {
	assert (hm);
	HtUU__CIter iter;
	const HtUU__Entry *entry;
	for (iter = HtUU__citer (&hm->inner); (entry = HtUU__CIter_get (&iter)) != NULL; HtUU__CIter_next (&iter)) {
		if (!cb (user, entry->key, entry->val)) {
			return;
		}
	}
}
