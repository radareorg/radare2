/* radare2 - BSD 3 Clause License - 2016-2021 - crowell */

#ifndef HT_TYPE
#error HT_TYPE should be defined before including this header
#endif

#undef HtName_
#undef Ht_
#undef HT_
#undef KEY_TYPE
#undef VALUE_TYPE
#undef KEY_TO_HASH
#undef HT_NULL_VALUE

#if HT_TYPE == 1
#define HtName_(name) name##PP
#define Ht_(name) ht_pp_##name
#define HT_(name) HtPP##name
#define KEY_TYPE void *
#define VALUE_TYPE void *
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE NULL
#elif HT_TYPE == 2
#define HtName_(name) name##UP
#define Ht_(name) ht_up_##name
#define HT_(name) HtUP##name
#define KEY_TYPE ut64
#define VALUE_TYPE void *
#define KEY_TO_HASH(x) ((ut32)(x))
#define HT_NULL_VALUE 0
#elif HT_TYPE == 3
#define HtName_(name) name##UU
#define Ht_(name) ht_uu_##name
#define HT_(name) HtUU##name
#define KEY_TYPE ut64
#define VALUE_TYPE ut64
#define KEY_TO_HASH(x) ((ut32)(x))
#define HT_NULL_VALUE 0
#else
#define HtName_(name) name##PU
#define Ht_(name) ht_pu_##name
#define HT_(name) HtPU##name
#define KEY_TYPE void *
#define VALUE_TYPE ut64
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE 0
#endif

#include "ls.h"
#include "types.h"

/* Kv represents a single key/value element in the hashtable */
typedef struct Ht_(kv) {
	KEY_TYPE key;
	VALUE_TYPE value;
	ut32 key_len;
	ut32 value_len;
} HT_(Kv);

typedef void (*HT_(KvFreeFunc))(HT_(Kv) *);
typedef KEY_TYPE (*HT_(DupKey))(const KEY_TYPE);
typedef VALUE_TYPE (*HT_(DupValue))(const VALUE_TYPE);
typedef ut32 (*HT_(CalcSizeK))(const KEY_TYPE);
typedef ut32 (*HT_(CalcSizeV))(const VALUE_TYPE);
typedef ut32 (*HT_(HashFunction))(const KEY_TYPE);
typedef int (*HT_(ListComparator))(const KEY_TYPE, const KEY_TYPE);
typedef bool (*HT_(ForeachCallback))(void *user, const KEY_TYPE, const VALUE_TYPE);

typedef struct Ht_(bucket_t) {
	HT_(Kv) *arr;
	ut32 count;
} HT_(Bucket);

/* Options contain all the settings of the hashtable */
typedef struct Ht_(options_t) {
	HT_(ListComparator) cmp;   	// Function for comparing values. Returns 0 if eq.
	HT_(HashFunction) hashfn;  	// Function for hashing items in the hash table.
	HT_(DupKey) dupkey;		// Function for making a copy of key
	HT_(DupValue) dupvalue;  	// Function for making a copy of value
	HT_(CalcSizeK) calcsizeK;	// Function to determine the key's size
	HT_(CalcSizeV) calcsizeV;  	// Function to determine the value's size
	HT_(KvFreeFunc) freefn;  	// Function to free the keyvalue store
	size_t elem_size;		// Size of each HtKv element (useful for subclassing like SdbKv)
} HT_(Options);

/* Ht is the hashtable structure */
typedef struct Ht_(t) {
	ut32 size;	  // size of the hash table in buckets.
	ut32 count;	  // number of stored elements.
	HT_(Bucket)* table;  // Actual table.
	ut32 prime_idx;
	HT_(Options) opt;
} HtName_(Ht);

// Create a new Ht with the provided Options
SDB_API HtName_(Ht)* Ht_(new_opt)(HT_(Options) *opt);
// Destroy a hashtable and all of its entries.
SDB_API void Ht_(free)(HtName_(Ht)* ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
SDB_API bool Ht_(insert)(HtName_(Ht)* ht, const KEY_TYPE key, VALUE_TYPE value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool Ht_(update)(HtName_(Ht)* ht, const KEY_TYPE key, VALUE_TYPE value);
// Update the key of an element in the hashtable
SDB_API bool Ht_(update_key)(HtName_(Ht)* ht, const KEY_TYPE old_key, const KEY_TYPE new_key);
// Delete a key from the hashtable.
SDB_API bool Ht_(delete)(HtName_(Ht)* ht, const KEY_TYPE key);
// Find the value corresponding to the matching key.
SDB_API VALUE_TYPE Ht_(find)(HtName_(Ht)* ht, const KEY_TYPE key, bool* found);
// Iterates over all elements in the hashtable, calling the cb function on each Kv.
// If the cb returns false, the iteration is stopped.
// cb should not modify the hashtable.
// NOTE: cb can delete the current element, but it should be avoided
SDB_API void Ht_(foreach)(HtName_(Ht) *ht, HT_(ForeachCallback) cb, void *user);

SDB_API HT_(Kv)* Ht_(find_kv)(HtName_(Ht)* ht, const KEY_TYPE key, bool* found);
SDB_API bool Ht_(insert_kv)(HtName_(Ht) *ht, HT_(Kv) *kv, bool update);

#undef HT_TYPE
