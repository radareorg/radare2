/* radare2 - LGPL - Copyright 2017 - condret */

#ifndef R_ID_STORAGE_H
#define R_ID_STORAGE_H

#include <r_util.h>
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

R_API RIDStorage *r_id_storage_new(ut32 start_id, ut32 last_id);
R_API bool r_id_storage_set(RIDStorage *storage, void *data, ut32 id);
R_API bool r_id_storage_add(RIDStorage *storage, void *data, ut32 *id);
R_API void *r_id_storage_get(RIDStorage *storage, ut32 id);
R_API void r_id_storage_delete(RIDStorage *storage, ut32 id);
R_API void *r_id_storage_take(RIDStorage *storage, ut32 id);
R_API bool r_id_storage_foreach(RIDStorage *storage, RIDStorageForeachCb cb, void *user);
R_API void r_id_storage_free(RIDStorage *storage);

#ifdef __cplusplus
}
#endif

#endif
