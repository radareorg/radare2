#ifndef SDB_HT_SU_H
#define SDB_HT_SU_H

/*
 * This header provides a hashtable HtSU that has char* as key and ut64 as
 * value (a "stringmap"). The hashtable takes ownership of the keys by making a
 * copy of the key, and will free the pointers once they are removed from the
 * hashtable.
 */

#include "sdb/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t ut64;

typedef struct HtSU_t HtSU;

typedef bool (*HtSUForEachCallback)(void *user, const char *key, const ut64 value);

SDB_API HtSU* ht_su_new0(void);
SDB_API void ht_su_free(HtSU *hm);
SDB_API bool ht_su_insert(HtSU *hm, const char *key, ut64 value);
SDB_API bool ht_su_update(HtSU *hm, const char *key, ut64 value);
SDB_API bool ht_su_update_key(HtSU *hm, const char *old_key, const char *new_key);
SDB_API bool ht_su_delete(HtSU *hm, const char *key);
SDB_API ut64 ht_su_find(HtSU *hm, const char *key, bool* found);
SDB_API void ht_su_foreach(HtSU *hm, HtSUForEachCallback cb, void *user);

#ifdef __cplusplus
}
#endif

#endif
