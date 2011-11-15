#ifndef _INCLUDE_DB_R_
#define _INCLUDE_DB_R_

#include "r_types.h"
#include "r_util.h"

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
	struct r_db_block_t *blocks[R_DB_KEYS];
	int blocks_sz[R_DB_KEYS];
	void *cb_user;
	int (*cb_free)(void *db, const void *item, void *user);
} RDatabase;

typedef struct r_db_iter_t {
	struct r_db_t *db;
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
R_API RPairItem *r_pair_item_new ();
R_API void r_pair_item_free (RPairItem*);

R_API RPair *r_pair_new ();
R_API RPair *r_pair_new_from_file (const char *file);
R_API void r_pair_free (RPair *p);
R_API void r_pair_delete (RPair *p, const char *name);
R_API char *r_pair_get (RPair *p, const char *name);
R_API void r_pair_set (RPair *p, const char *name, const char *value);
R_API RList *r_pair_list (RPair *p, const char *domain);
R_API void r_pair_set_sync_dir (RPair *p, const char *dir);
R_API void r_pair_load (RPair *p);
R_API void r_pair_sync (RPair *p);
R_API void r_pair_reset (RPair *p);
/* */
R_API struct r_db_t *r_db_new();
R_API struct r_db_block_t *r_db_block_new();
R_API int r_db_add_id(struct r_db_t *db, int off, int size);
R_API int r_db_add(struct r_db_t *db, void *b);
R_API int r_db_add_unique(struct r_db_t *db, void *b);
R_API void **r_db_get(struct r_db_t *db, int key, const ut8 *b);
R_API void *r_db_get_cur(void **ptr);
R_API int r_db_delete(struct r_db_t *db, const void *b);
R_API void **r_db_get_next(void **ptr);
R_API struct r_db_iter_t *r_db_iter(struct r_db_t *db, int key, const ut8 *b);
R_API void *r_db_iter_cur(struct r_db_iter_t *iter);
R_API int r_db_iter_next(struct r_db_iter_t *iter);
R_API void *r_db_iter_prev(struct r_db_iter_t *iter);
R_API struct r_db_iter_t *r_db_iter_new(struct r_db_t *db, int key);
R_API struct r_db_iter_t *r_db_iter_free(struct r_db_iter_t *iter);
R_API int r_db_free(struct r_db_t *db);
//R_API int r_db_push(struct r_db_t *db, const ut8 *b);
//R_API ut8 *r_db_pop(struct r_db_t *db);
#endif

#endif
