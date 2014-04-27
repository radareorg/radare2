#ifndef R2_DB_H
#define R2_DB_H

#include "r_types.h"
#include "r_util.h"
#include "sdb.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_db);

// TODO: add support for network. (udp). memcache, with hooks
typedef struct r_pair_t {
	char *dir;
	char *file;
	void *sdb;
	RHashTable *ht;
	RList *dbs;
} RPair;

#define R_DB_KEYS 256

typedef struct r_db_block_t {
	void **data; /* { 0x80380, 0x80380, 0 } */
	struct r_db_block_t *childs[256];
} RDatabaseBlock;

#define R_DB_INDEXOF(type, member) \
  (int)((size_t)((&((type *)0)->member)))

typedef struct r_db_t {
	int id_min;
	int id_max;
	RDatabaseBlock *blocks[R_DB_KEYS];
	int blocks_sz[R_DB_KEYS];
	void *cb_user;
	int (*cb_free)(void *db, const void *item, void *user);
} RDatabase;

typedef struct r_db_iter_t {
	RDatabase *db;
	int key;       /* key to be used */
	int size;      /* key size */
	int path[256]; /* for each depth level */
	int ptr;       /* pointer in block nodes (repeated childs) */
	void *cur;
} RDatabaseIter;

/* table */
typedef struct r_db_table_t {
	char *name;
	int nelems;
	char *fmt;
	char *args;
	int *offset;
} RDatabaseTable;

#if 0
it = r_db_iterator (db);
while (r_db_iter_next(it)) {
	f = (RAnalFcn*) r_db_iter_get (it);
	/* ... */
}
#endif

typedef struct r_pair_item_t {
	char *k, *v;
} RPairItem;

#ifdef R_API
R_API RPairItem *r_pair_item_new();
R_API void r_pair_item_free(RPairItem*);

R_API int r_pair_load(RPair *p, const char *f);
R_API int r_pair_save(RPair *p, const char *f);
R_API RPair *r_pair_new();
R_API RPair *r_pair_new_from_file(const char *file);
R_API void r_pair_free(RPair *p);
R_API void r_pair_delete(RPair *p, const char *name);
R_API char *r_pair_get(RPair *p, const char *name);
R_API void r_pair_set(RPair *p, const char *name, const char *value);
R_API RList *r_pair_list(RPair *p, const char *domain);
R_API void r_pair_set_sync_dir(RPair *p, const char *dir);
R_API int r_pair_sync(RPair *p);
R_API void r_pair_reset(RPair *p);
/* */
R_API RDatabase *r_db_new();
R_API RDatabaseBlock *r_db_block_new();
R_API int r_db_add_id(RDatabase *db, int off, int size);
R_API int r_db_add(RDatabase *db, void *b);
R_API int r_db_add_unique(RDatabase *db, void *b);
R_API void **r_db_get(RDatabase *db, int key, const ut8 *b);
R_API void *r_db_get_cur(void **ptr);
R_API int r_db_delete(RDatabase *db, const void *b);
R_API void **r_db_get_next(void **ptr);
R_API RDatabaseIter *r_db_iter(RDatabase *db, int key, const ut8 *b);
R_API void *r_db_iter_cur(RDatabaseIter *iter);
R_API int r_db_iter_next(RDatabaseIter *iter);
R_API void *r_db_iter_prev(RDatabaseIter *iter);
R_API RDatabaseIter *r_db_iter_new(RDatabase *db, int key);
R_API RDatabaseIter *r_db_iter_free(RDatabaseIter *iter);
R_API int r_db_free(RDatabase *db);
//R_API int r_db_push(RDatabase *db, const ut8 *b);
//R_API ut8 *r_db_pop(RDatabase *db);
#endif
#ifdef __cplusplus
}
#endif

#endif
