#ifndef __SDB_HT_H
#define __SDB_HT_H

#include "ht.h"

/** keyvalue pair **/
typedef struct sdb_kv {
	//sub of HtKv so we can cast safely
	char *key;
	char *value;
	ut32 key_len;
	ut32 value_len;
	ut32 cas;
	ut64 expire;
} SdbKv;

SDB_API SdbKv* sdb_kv_new2(const char *k, int kl, const char *v, int vl);
extern SdbKv* sdb_kv_new(const char *k, const char *v);
extern ut32 sdb_hash(const char *key);
extern void sdb_kv_free(SdbKv *kv);

SdbHash* sdb_ht_new(void);
// Destroy a hashtable and all of its entries.
void sdb_ht_free(SdbHash* ht);
void sdb_ht_free_deleted(SdbHash* ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
bool sdb_ht_insert(SdbHash* ht, const char* key, const char* value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
bool sdb_ht_insert_kvp(SdbHash* ht, SdbKv *kvp, bool update);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
bool sdb_ht_update(SdbHash* ht, const char* key, const char* value);
// Delete a key from the hashtable.
bool sdb_ht_delete(SdbHash* ht, const char* key);
// Find the value corresponding to the matching key.
char* sdb_ht_find(SdbHash* ht, const char* key, bool* found);
// Find the KeyValuePair corresponding to the matching key.
SdbKv* sdb_ht_find_kvp(SdbHash* ht, const char* key, bool* found);

#endif // __SDB_HT_H
