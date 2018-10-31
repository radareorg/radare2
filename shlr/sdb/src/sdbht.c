#include "sdbht.h"

void sdbkv_fini(SdbKv *kv) {
	free (kv->base.key);
	free (kv->base.value);
}

SDB_API SdbHt* sdb_ht_new() {
	SdbHt *ht = ht_new ((DupValue)strdup, (HtKvFreeFunc)sdbkv_fini, (CalcSize)strlen);
	if (ht) {
		ht->elem_size = sizeof (SdbKv);
	}
	return ht;
}

static bool sdb_ht_internal_insert(SdbHt* ht, const char* key,
				    const char* value, bool update) {
	if (!ht || !key || !value) {
		return false;
	}
	SdbKv kvp = {{ 0 }};
	kvp.base.key = strdup ((void *)key);
	if (!kvp.base.key) {
		goto err;
	}
	kvp.base.value = strdup ((void *)value);
	if (!kvp.base.value) {
		goto err;
	}
	kvp.base.key_len = strlen ((void *)kvp.base.key);
	kvp.base.value_len = strlen ((void *)kvp.base.value);
	kvp.expire = 0;
	return ht_insert_kv (ht, (HtKv*)&kvp, update);

 err:
	free (kvp.base.key);
	free (kvp.base.value);
	return false;
}

SDB_API bool sdb_ht_insert(SdbHt* ht, const char* key, const char* value) {
	return sdb_ht_internal_insert (ht, key, value, false);
}

SDB_API bool sdb_ht_insert_kvp(SdbHt* ht, SdbKv *kvp, bool update) {
	return ht_insert_kv (ht, (HtKv*)kvp, update);
}

SDB_API bool sdb_ht_update(SdbHt *ht, const char *key, const char*value) {
	return sdb_ht_internal_insert (ht, key, value, true);
}

SDB_API SdbKv* sdb_ht_find_kvp(SdbHt* ht, const char* key, bool* found) {
	return (SdbKv *)ht_find_kv (ht, key, found);
}

SDB_API char* sdb_ht_find(SdbHt* ht, const char* key, bool* found) {
	return (char *)ht_find (ht, key, found);
}

SDB_API void sdb_ht_free(SdbHt *ht) {
	ht_free (ht);
}

SDB_API bool sdb_ht_delete(SdbHt* ht, const char *key) {
	return ht_delete (ht, key);
}
