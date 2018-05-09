/* radare2 - BSD 3 Clause License - 2016 - crowell */

#ifndef __HT_H
#define __HT_H

#include "ls.h"
#include "types.h"

/* tune the hashtable */
#define INSERTORDER 0
#define GROWABLE 0
#define USE_KEYLEN 1
#define EXCHANGE 1

typedef struct ht_kv {
	char *key;
	void *value;
	ut32 key_len;
	ut32 value_len;
} HtKv;

typedef void (*HtKvFreeFunc)(HtKv *);
typedef char* (*DupKey)(void *);
typedef char* (*DupValue)(void *);
typedef size_t (*CalcSize)(void *);
typedef ut32 (*HashFunction)(const char*);
typedef int (*ListComparator)(const char *a, const char *b);
typedef bool (*HtForeachCallback)(void *user, const char *k, void *v);


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
	SdbList /*<SdbKv>*/** table;  // Actual table.
	SdbList* deleted;
	ut32 load_factor;  	// load factor before doubling in size.
	ut32 prime_idx;
#if INSERTORDER
	SdbList* list;
#endif
} SdbHash;

// Create a new RHashTable.
// If hashfunction is NULL it will be used sdb_hash internally
// If keydup or valdup are null it will be used an assignment
// If keySize or valueSize are null it will be used strlen internally
SDB_API SdbHash* ht_new(DupValue valdup, HtKvFreeFunc pair_free, CalcSize valueSize);
// Destroy a hashtable and all of its entries.
SDB_API void ht_free(SdbHash* ht);
SDB_API void ht_free_deleted(SdbHash* ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
SDB_API bool ht_insert(SdbHash* ht, const char* key, void* value);
//Insert a new HtKv in the hashtable
SDB_API bool ht_insert_kv(SdbHash *ht, HtKv *kv, bool update);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool ht_update(SdbHash* ht, const char* key, void* value);
// Delete a key from the hashtable.
SDB_API bool ht_delete(SdbHash* ht, const char* key);
// Find the value corresponding to the matching key.
SDB_API void* ht_find(SdbHash* ht, const char* key, bool* found);
HtKv* ht_find_kv(SdbHash* ht, const char* key, bool* found);
SDB_API void ht_foreach(SdbHash *ht, HtForeachCallback cb, void *user);
SDB_API SdbList* ht_foreach_list(SdbHash *ht, bool sorted);

#endif // __HT_H
