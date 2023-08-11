#ifndef SDB_HT_PU_H
#define SDB_HT_PU_H

/*
 * This header provides a hashtable HtPU that has void* as key and ut64 as
 * value. The hashtable does not take ownership of the keys, and so will not
 * free the pointers once they are removed from the hashtable.
 */

#include "sdb/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t ut64;

typedef struct HtPU_t HtPU;

typedef bool (*HtPUForEachCallback)(void *user, const void *key, const ut64 value);

SDB_API HtPU* ht_pu_new0(void);
SDB_API void ht_pu_free(HtPU *hm);
SDB_API bool ht_pu_insert(HtPU *hm, void *key, ut64 value);
SDB_API bool ht_pu_update(HtPU *hm, void *key, ut64 value);
SDB_API bool ht_pu_update_key(HtPU *hm, void *old_key, void *new_key);
SDB_API bool ht_pu_delete(HtPU *hm, void *key);
SDB_API ut64 ht_pu_find(HtPU *hm, void *key, bool* found);
SDB_API void ht_pu_foreach(HtPU *hm, HtPUForEachCallback cb, void *user);

#ifdef __cplusplus
}
#endif

#endif
