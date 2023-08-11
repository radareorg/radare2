#ifndef SDB_HT_UU_H_
#define SDB_HT_UU_H_

/*
 * This header provides a hashtable Ht that has ut64 as key and ut64 as value.
 */

#include "sdb/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HtUU_t HtUU;
typedef bool (*HtUUForEachCallback)(void *user, const ut64 key, const ut64 value);

SDB_API HtUU* ht_uu_new0(void);
SDB_API void ht_uu_free(HtUU *hm);
SDB_API bool ht_uu_insert(HtUU *hm, const ut64 key, ut64 value);
SDB_API bool ht_uu_update(HtUU *hm, const ut64 key, ut64 value);
SDB_API bool ht_uu_update_key(HtUU *hm, const ut64 old_key, const ut64 new_key);
SDB_API bool ht_uu_delete(HtUU *hm, const ut64 key);
SDB_API ut64 ht_uu_find(HtUU *hm, const ut64 key, bool* found);
SDB_API void ht_uu_foreach(HtUU *hm, HtUUForEachCallback cb, void *user);

#ifdef __cplusplus
}
#endif

#endif
