#include "ls.h"
#include "types.h"

typedef void (*HtKvFreeFunc)(void *);

/** ht **/
typedef struct ht_entry_t {
	SdbListIter *iter;
	ut32 hash;
	void *data;
} SdbHashEntry;

typedef struct ht_t {
	SdbList *list;
	SdbHashEntry *table;
	ut32 size;
	ut32 rehash;
	ut32 max_entries;
	ut32 size_index;
	ut32 entries;
	ut32 deleted_entries;
} SdbHash;

SdbHash* ht_new(SdbListFree f);
void ht_free(SdbHash *ht);
//void ht_set(SdbHash *ht, ut32 hash, void *data);
SdbHashEntry* ht_search(SdbHash *ht, ut32 hash);
void *ht_lookup(SdbHash *ht, ut32 hash);
void ht_set(SdbHash *ht, ut32 hash, void *data);
int ht_insert(SdbHash *ht, ut32 hash, void *data, SdbListIter *iter);
void ht_delete_entry(SdbHash *ht, SdbHashEntry *entry);
