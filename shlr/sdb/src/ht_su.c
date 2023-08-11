/* sdb - MIT - Copyright 2018-2023 - ret2libc, pancake, luc-tielen */

#include <stdint.h>
#include "sdb/ht_su.h"
#include "sdb/heap.h"
#include "sdb/sdb.h"
#include "sdb/cwisstable.h"

static inline void string_copy(void *dst, const void *src);
static inline void string_dtor(void *val);
static inline size_t string_hash(const void *val);
static inline bool string_eq(const void *a, const void *b);

CWISS_DECLARE_FLAT_HASHMAP(HtSU_, char*, ut64, string_copy, string_dtor, string_hash, string_eq);

struct HtSU_t {
	HtSU_ inner;
};

static inline void string_copy(void *dst_, const void *src_) {
  const HtSU__Entry *src = (const HtSU__Entry *) src_;
  HtSU__Entry *dst = (HtSU__Entry *) dst_;

  const size_t len = strlen (src->key);
  dst->key = (char*) sdb_gh_malloc (len + 1);
  dst->val = src->val;
  memcpy (dst->key, src->key, len + 1);
}

static inline void string_dtor(void *val) {
  char *str = *(char**)val;
  sdb_gh_free (str);
}

static inline size_t string_hash(const void *val) {
  const char *str = *(const char *const *)val;
  const size_t len = strlen (str);
  CWISS_FxHash_State state = 0;
  CWISS_FxHash_Write (&state, str, len);
  return state;
}

static inline bool string_eq(const void *a, const void *b) {
  const char *ap = *(const char* const *)a;
  const char *bp = *(const char* const *)b;
  return strcmp (ap, bp) == 0;
}

SDB_API HtSU* ht_su_new0(void) {
	HtSU *hm = (HtSU*) sdb_gh_calloc (1, sizeof (HtSU));
	if (hm) {
		hm->inner = HtSU__new (0);
	}
	return hm;
}

SDB_API void ht_su_free(HtSU *hm) {
	if (hm) {
		HtSU__destroy (&hm->inner);
		sdb_gh_free (hm);
	}
}

SDB_API bool ht_su_insert(HtSU *hm, const char *key, ut64 value) {
	assert (hm && key);

	char *key_copy = sdb_strdup (key);
	if (!key_copy) {
		return false;
	}

	HtSU__Entry entry = { .key = key_copy, .val = value };
	HtSU__Insert result = HtSU__insert (&hm->inner, &entry);
	if (!result.inserted) {
		sdb_gh_free (key_copy);
		return false;
	}
	return true;
}

SDB_API bool ht_su_update(HtSU *hm, const char *key, ut64 value) {
	assert (hm && key);

	char *key_copy = sdb_strdup (key);
	if (!key_copy) {
		return false;
	}

	HtSU__Entry entry = { .key = key_copy, .val = value };
	HtSU__Insert insert_result = HtSU__insert (&hm->inner, &entry);
	if (!insert_result.inserted) {
		sdb_gh_free (key_copy);

		HtSU__Entry *existing_entry = HtSU__Iter_get (&insert_result.iter);
		existing_entry->val = value;
	}

	return true;
}

// Update the key of an element in the hashtable
SDB_API bool ht_su_update_key(HtSU *hm, const char *old_key, const char *new_key) {
	assert (hm && old_key && new_key);

	HtSU__Iter iter = HtSU__find (&hm->inner, (const HtSU__Key*) &old_key);
	HtSU__Entry *entry = HtSU__Iter_get (&iter);
	if (!entry) {
		return false;
	}

	// Do nothing if keys are the same
	if (SDB_UNLIKELY (strcmp (old_key, new_key) == 0)) {
		return true;
	}

	char *key_copy = sdb_strdup (new_key);
	if (!key_copy) {
		return false;
	}

	// First try inserting the new key
	HtSU__Entry new_entry = { .key = key_copy, .val = entry->val };
	HtSU__Insert result = HtSU__insert (&hm->inner, &new_entry);
	if (!result.inserted) {
		sdb_gh_free (key_copy);
		return false;
	}

	// Then remove entry for the old key
	HtSU__erase_at (iter);
	return true;
}

SDB_API bool ht_su_delete(HtSU *hm, const char *key) {
	assert (hm && key);
	return HtSU__erase (&hm->inner, (const HtSU__Key*) &key);
}

SDB_API ut64 ht_su_find(HtSU *hm, const char *key, bool* found) {
	assert (hm && key);

	if (found) {
		*found = false;
	}

	HtSU__Iter iter = HtSU__find (&hm->inner, (const HtSU__Key*) &key);
	HtSU__Entry *entry = HtSU__Iter_get (&iter);
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
SDB_API void ht_su_foreach(HtSU *hm, HtSUForEachCallback cb, void *user) {
	assert (hm);
	HtSU__CIter iter;
	const HtSU__Entry *entry;

	for (iter = HtSU__citer (&hm->inner); (entry = HtSU__CIter_get (&iter)) != NULL; HtSU__CIter_next (&iter)) {
		if (!cb (user, entry->key, entry->val)) {
			return;
		}
	}
}
