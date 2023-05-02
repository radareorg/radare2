/* sdb - MIT - Copyright 2011-2022 - pancake */

#include "sdb/ht.h"

void sdbkv_fini(SdbKv *kv) {
	sdb_gh_free (kv->base.key);
	sdb_gh_free (kv->base.value);
}

SDB_API HtPP* sdb_ht_new(void) {
	HtPP *ht = ht_pp_new ((HtPPDupValue)sdb_strdup, (HtPPKvFreeFunc)sdbkv_fini, (HtPPCalcSizeV)strlen);
	if (ht) {
		ht->opt.elem_size = sizeof (SdbKv);
	}
	return ht;
}

static bool sdb_ht_internal_insert(HtPP* ht, const char* key, const char* value, bool update) {
	if (!ht || !key || !*key || !value) {
		return false;
	}
	SdbKv kvp = {{ 0 }};
	kvp.base.key = sdb_strdup (key);
	if (!kvp.base.key) {
		goto err;
	}
	kvp.base.value = sdb_strdup (value);
	if (!kvp.base.value) {
		goto err;
	}
	kvp.base.key_len = strlen ((const char *)kvp.base.key);
	kvp.base.value_len = strlen ((const char *)kvp.base.value);
	kvp.expire = 0;
	return ht_pp_insert_kv (ht, (HtPPKv*)&kvp, update);

 err:
	sdb_gh_free (kvp.base.key);
	sdb_gh_free (kvp.base.value);
	return false;
}

SDB_API bool sdb_ht_insert(HtPP* ht, const char* key, const char* value) {
	return sdb_ht_internal_insert (ht, key, value, false);
}

SDB_API bool sdb_ht_insert_kvp(HtPP* ht, SdbKv *kvp, bool update) {
	return ht_pp_insert_kv (ht, (HtPPKv*)kvp, update);
}

SDB_API bool sdb_ht_update(HtPP *ht, const char *key, const char* value) {
	return sdb_ht_internal_insert (ht, key, value, true);
}

SDB_API SdbKv* sdb_ht_find_kvp(HtPP* ht, const char* key, bool* found) {
	return (SdbKv *)ht_pp_find_kv (ht, key, found);
}

SDB_API char* sdb_ht_find(HtPP* ht, const char* key, bool* found) {
	return (char *)ht_pp_find (ht, key, found);
}

SDB_API void sdb_ht_free(HtPP *ht) {
	ht_pp_free (ht);
}

SDB_API bool sdb_ht_delete(HtPP* ht, const char *key) {
	return ht_pp_delete (ht, key);
}
