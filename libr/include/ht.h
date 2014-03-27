#ifndef R2_HT_H
#define R2_HT_H

#ifdef __cplusplus
extern "C" {
#endif

/** hashtable **/
typedef struct r_hashtable_entry_t {
	ut32 hash;
	void *data;
} RHashTableEntry;

typedef struct r_hashtable_t {
	RHashTableEntry *table;
	ut32 size;
	ut32 rehash;
	ut32 max_entries;
	ut32 size_index;
	ut32 entries;
	ut32 deleted_entries;
} RHashTable;

typedef struct r_hashtable64_entry_t {
	ut64 hash;
	void *data;
} RHashTable64Entry;

typedef struct r_hashtable64_t {
	RHashTable64Entry *table;
	ut64 size;
	ut64 rehash;
	ut64 max_entries;
	ut64 size_index;
	ut64 entries;
	ut64 deleted_entries;
} RHashTable64;

R_API RHashTable* r_hashtable_new(void);
R_API void r_hashtable_free(RHashTable *ht);
R_API void *r_hashtable_lookup(RHashTable *ht, ut32 hash);
R_API boolt r_hashtable_insert(RHashTable *ht, ut32 hash, void *data);
R_API void r_hashtable_remove(RHashTable *ht, ut32 hash);

R_API RHashTable64* r_hashtable64_new(void);
R_API void r_hashtable64_free(RHashTable64 *ht);
R_API void *r_hashtable64_lookup(RHashTable64 *ht, ut64 hash);
R_API boolt r_hashtable64_insert(RHashTable64 *ht, ut64 hash, void *data);
R_API void r_hashtable64_remove(RHashTable64 *ht, ut64 hash);

#ifdef __cplusplus
}
#endif
#endif
