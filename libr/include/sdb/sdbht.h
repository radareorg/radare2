#ifndef __SDB_HT_H
#define __SDB_HT_H

#include "ht.h"

/** keyvalue pair **/
typedef struct sdb_kv {
	//sub of HtKv so we can cast safely
	HtKv base;
	ut32 cas;
	ut64 expire;
} SdbKv;

static inline char *sdbkv_key(const SdbKv *kv) {
	return kv->base.key;
}

static inline char *sdbkv_value(const SdbKv *kv) {
	return (char *)kv->base.value;
}

static inline ut32 sdbkv_key_len(const SdbKv *kv) {
	return kv->base.key_len;
}

static inline ut32 sdbkv_value_len(const SdbKv *kv) {
	return kv->base.value_len;
}

SDB_API SdbKv* sdbkv_new2(const char *k, int kl, const char *v, int vl);
SDB_API SdbKv* sdbkv_new(const char *k, const char *v);
extern void sdbkv_free(SdbKv *kv);

extern ut32 sdb_hash(const char *key);

SDB_API SdbHt* sdb_ht_new(void);
// Destroy a hashtable and all of its entries.
SDB_API void sdb_ht_free(SdbHt* ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
SDB_API bool sdb_ht_insert(SdbHt* ht, const char* key, const char* value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool sdb_ht_insert_kvp(SdbHt* ht, SdbKv *kvp, bool update);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool sdb_ht_update(SdbHt* ht, const char* key, const char* value);
// Delete a key from the hashtable.
SDB_API bool sdb_ht_delete(SdbHt* ht, const char* key);
// Find the value corresponding to the matching key.
SDB_API char* sdb_ht_find(SdbHt* ht, const char* key, bool* found);
// Find the KeyValuePair corresponding to the matching key.
SDB_API SdbKv* sdb_ht_find_kvp(SdbHt* ht, const char* key, bool* found);

#endif // __SDB_HT_H
