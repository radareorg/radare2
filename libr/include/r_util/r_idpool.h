/* radare2 - LGPL - Copyright 2017-2018 - condret */

#ifndef R_ID_STORAGE_H
#define R_ID_STORAGE_H

#include <r_util/r_pool.h>
#include <r_util/r_queue.h>
#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_id_pool_t {
	ut32 start_id;
	ut32 last_id;
	ut32 next_id;
	RQueue *freed_ids;
} RIDPool;

R_API RIDPool *r_id_pool_new(ut32 start_id, ut32 last_id);
R_API bool r_id_pool_grab_id(RIDPool *pool, ut32 *grabber);
R_API bool r_id_pool_kick_id(RIDPool *pool, ut32 kick);
R_API void r_id_pool_free(RIDPool *pool);

typedef struct r_id_storage_t {
	RIDPool *pool;
	void **data;
	ut32 top_id;
	ut32 size;
} RIDStorage;

typedef bool (*RIDStorageForeachCb)(void *user, void *data, ut32 id);
typedef bool (*ROIDStorageCompareCb)(void *in, void *incoming, void *user, int *cmp_res);

R_API RIDStorage *r_id_storage_new(ut32 start_id, ut32 last_id);
R_API bool r_id_storage_set(RIDStorage *storage, void *data, ut32 id);
R_API bool r_id_storage_add(RIDStorage *storage, void *data, ut32 *id);
R_API void *r_id_storage_get(RIDStorage *storage, ut32 id);
R_API bool r_id_storage_get_next(RIDStorage *storage, ut32 *id);
R_API bool r_id_storage_get_prev(RIDStorage *storage, ut32 *id);
R_API void r_id_storage_delete(RIDStorage *storage, ut32 id);
R_API void *r_id_storage_take(RIDStorage *storage, ut32 id);
R_API bool r_id_storage_foreach(RIDStorage *storage, RIDStorageForeachCb cb, void *user);
R_API void r_id_storage_free(RIDStorage *storage);
R_API RList *r_id_storage_list(RIDStorage *s);
R_API bool r_id_storage_get_lowest(RIDStorage *storage, ut32 *id);
R_API bool r_id_storage_get_highest(RIDStorage *storage, ut32 *id);

typedef struct r_ordered_id_storage_t {
	ut32 *permutation;
	ut32 psize;
	ut32 ptop;
	RIDStorage *data;
	ROIDStorageCompareCb cmp;
} ROIDStorage;

R_API ROIDStorage *r_oids_new(ut32 start_id, ut32 last_id);
R_API void *r_oids_get(ROIDStorage *storage, ut32 id);
R_API void *r_oids_oget(ROIDStorage *storage, ut32 od);
R_API bool r_oids_get_id(ROIDStorage *storage, ut32 od, ut32 *id);
R_API bool r_oids_get_od(ROIDStorage *storage, ut32 id, ut32 *od);
R_API bool r_oids_to_front(ROIDStorage *storage, const ut32 id);
R_API bool r_oids_to_rear(ROIDStorage *storage, const ut32 id);
R_API void r_oids_delete(ROIDStorage *storage, ut32 id);
R_API void r_oids_odelete(ROIDStorage *st, ut32 od);
R_API void r_oids_free(ROIDStorage *storage);
R_API bool r_oids_add(ROIDStorage *storage, void *data, ut32 *id, ut32 *od);
R_API void *r_oids_take(ROIDStorage *storage, ut32 id);
R_API void *r_oids_otake(ROIDStorage *st, ut32 od);
R_API bool r_oids_foreach(ROIDStorage* storage, RIDStorageForeachCb cb, void* user);
R_API bool r_oids_foreach_prev(ROIDStorage* storage, RIDStorageForeachCb cb, void* user);
R_API bool r_oids_insert(ROIDStorage *storage, void *data, ut32 *id, ut32 *od, void *user); 
R_API bool r_oids_sort(ROIDStorage *storage, void *user);
R_API ut32 r_oids_find (ROIDStorage *storage, void *incoming, void *user);
R_API void *r_oids_last(ROIDStorage *storage);
R_API void *r_oids_first(ROIDStorage *storage);

#ifdef __cplusplus
}
#endif

#endif
