/* radare2 - BSD 3 Clause License - 2016 - crowell */

#ifndef __HT_H
#define __HT_H

#include "ls.h"
#include "types.h"

typedef struct ht_kv {
	char *key;
	void *value;
	ut32 key_len;
	ut32 value_len;
} HtKv;

typedef void (*HtKvFreeFunc)(HtKv *);
typedef char* (*DupKey)(const void *);
typedef void* (*DupValue)(const void *);
typedef size_t (*CalcSize)(const void *);
typedef ut32 (*HashFunction)(const char *);
typedef int (*ListComparator)(const char *a, const char *b);
typedef bool (*HtForeachCallback)(void *user, const char *k, void *v);

typedef struct ht_bucket_t {
	HtKv *arr;
	ut32 count;
} HtBucket;

/** ht **/
typedef struct ht_t {
	ut32 size;	    	// size of the hash table in buckets.
	ut32 count;	   	// number of stored elements.
	ListComparator cmp;   	// Function for comparing values. Returns 0 if eq.
	HashFunction hashfn;  	// Function for hashing items in the hash table.
	DupKey dupkey;  		// Function for making a copy of key
	DupValue dupvalue;  	// Function for making a copy of value
	CalcSize calcsizeK;     // Function to determine the key's size
	CalcSize calcsizeV;  	// Function to determine the value's size
	HtKvFreeFunc freefn;  	// Function to free the keyvalue store
	HtBucket* table;  // Actual table.
	ut32 prime_idx;
	size_t elem_size;
} SdbHt;

// Create a new RHashTable.
// If hashfunction is NULL it will be used sdb_hash internally
// If keydup or valdup are null it will be used an assignment
// If keySize or valueSize are null it will be used strlen internally
SDB_API SdbHt* ht_new(DupValue valdup, HtKvFreeFunc pair_free, CalcSize valueSize);
SDB_API SdbHt* ht_new_size(ut32 initial_size, DupValue valdup, HtKvFreeFunc pair_free, CalcSize valueSize);
// Destroy a hashtable and all of its entries.
SDB_API void ht_free(SdbHt* ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
SDB_API bool ht_insert(SdbHt* ht, const char* key, void* value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool ht_update(SdbHt* ht, const char* key, void* value);
// Delete a key from the hashtable.
SDB_API bool ht_delete(SdbHt* ht, const char* key);
// Find the value corresponding to the matching key.
SDB_API void* ht_find(SdbHt* ht, const char* key, bool* found);
SDB_API void ht_foreach(SdbHt *ht, HtForeachCallback cb, void *user);

HtKv* ht_find_kv(SdbHt* ht, const char* key, bool* found);
bool ht_insert_kv(SdbHt *ht, HtKv *kv, bool update);

#endif // __HT_H
