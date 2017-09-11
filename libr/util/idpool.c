/* radare2 - LGPL - Copyright 2017 - condret */

#include <r_util.h>
#include <r_types.h>

ut32 get_msb(ut32 v) {
	int i;
	for (i = 31; i > (-1); i--) {
		if (v & (0x1U << i)) {
			return (v & (0x1U << i));
		}
	}
	return 0;
}

R_API RIDPool* r_id_pool_new(ut32 start_id, ut32 last_id) {
	RIDPool* pool = NULL;
	if (start_id < last_id) {
		pool = R_NEW0 (RIDPool);
		if (!pool) {
			return NULL;
		}
		pool->next_id = pool->start_id = start_id;
		pool->last_id = last_id;
	}
	return pool;
}

R_API bool r_id_pool_grab_id(RIDPool* pool, ut32* grabber) {
	if (!pool || !grabber) {
		return false;
	}
	if (pool->freed_ids) {
		ut32 grab = (ut32) (size_t)r_queue_dequeue (pool->freed_ids);
		*grabber = (ut32) grab;
		if (r_queue_is_empty (pool->freed_ids)) {
			r_queue_free (pool->freed_ids);
			pool->freed_ids = NULL;
		}
		return true;
	}
	if (pool->next_id < pool->last_id) {
		*grabber = pool->next_id;
		pool->next_id++;
		return true;
	}
	return false;
}

R_API bool r_id_pool_kick_id(RIDPool* pool, ut32 kick) {
	if (!pool || (kick < pool->start_id) || (pool->start_id == pool->next_id)) {
		return false;
	}
	if (kick == (pool->next_id - 1)) {
		pool->next_id--;
		return true;
	}
	if (!pool->freed_ids) {
		pool->freed_ids = r_queue_new (2);
	}
	r_queue_enqueue (pool->freed_ids, (void*) (size_t) kick);
	return true;
}

R_API void r_id_pool_free(RIDPool* pool) {
	if (pool && pool->freed_ids) {
		r_queue_free (pool->freed_ids);
	}
	free (pool);
}

R_API RIDStorage* r_id_storage_new(ut32 start_id, ut32 last_id) {
	RIDPool* pool;
	RIDStorage* storage = NULL;
	if ((start_id < 16) && (pool = r_id_pool_new (start_id, last_id))) {
		storage = R_NEW0 (RIDStorage);
		if (!storage) {
			r_id_pool_free (pool);
			return NULL;
		}
		storage->pool = pool;
	}
	return storage;
}

static bool id_storage_reallocate(RIDStorage* storage, ut32 size) {
	if (!storage) {
		return false;
	}
	void **data = realloc (storage->data, size * sizeof (void*));
	if (!data) {
		return false;
	}
	if (size > storage->size) {
		memset (data + storage->size, 0, (size - storage->size) * sizeof (void*));
	}
	storage->data = data;
	storage->size = size;
	return true;
}

R_API bool r_id_storage_set(RIDStorage* storage, void* data, ut32 id) {
	ut32 n;
	if (!storage || !storage->pool || (id >= storage->pool->next_id)) {
		return false;
	}
	n = get_msb (id + 1);
	if (n > (storage->size - (storage->size / 4))) {
		if (n < (storage->pool->last_id / 2)) {
			if (!id_storage_reallocate (storage, n * 2)) {
				return false;
			}
		} else if (n != (storage->pool->last_id)) {
			if (!id_storage_reallocate (storage, storage->pool->last_id)) {
				return false;
			}
		}
	}
	storage->data[id] = data;
	if (id > storage->top_id) {
		storage->top_id = id;
	}
	return true;
}

R_API bool r_id_storage_add(RIDStorage* storage, void* data, ut32* id) {
	if (!storage || !r_id_pool_grab_id (storage->pool, id)) {
		return false;
	}
	return r_id_storage_set (storage, data, *id);
}

R_API void* r_id_storage_get(RIDStorage* storage, ut32 id) {
	if (!storage || !storage->data || (storage->size <= id)) {
		return NULL;
	}
	return storage->data[id];
}

R_API void r_id_storage_delete(RIDStorage* storage, ut32 id) {
	if (!storage || !storage->data || (storage->size <= id)) {
		return;
	}
	storage->data[id] = NULL;
	if (id == storage->top_id) {
		while (storage->top_id && !storage->data[storage->top_id]) {
			storage->top_id--;
		}
		if (!storage->top_id) {
			if(storage->data[storage->top_id]) {
				id_storage_reallocate (storage, 2);
			} else {
				RIDPool* pool = r_id_pool_new (storage->pool->start_id, storage->pool->last_id);
				R_FREE (storage->data);
				storage->size = 0;
				r_id_pool_free (storage->pool);
				storage->pool = pool;
				return;
			}
		} else if ((storage->top_id + 1) < (storage->size / 4)) {
			id_storage_reallocate (storage, storage->size / 2);
		}
	}
	r_id_pool_kick_id (storage->pool, id);
}

R_API void* r_id_storage_take(RIDStorage* storage, ut32 id) {
	void* ret = r_id_storage_get (storage, id);
	r_id_storage_delete (storage, id);
	return ret;
}

R_API bool r_id_storage_foreach(RIDStorage* storage, RIDStorageForeachCb cb, void* user) {
	ut32 i;
	if (!cb || !storage || !storage->data) {
		return false;
	}
	for (i = 0; i < storage->top_id; i++) {
		if (storage->data[i]) {
			if (!cb (user, storage->data[i], i)) {
				return false;
			}
		}
	}
	if (storage->data[i]) {
		return cb (user, storage->data[i], i);
	}
	return true;
}

R_API void r_id_storage_free(RIDStorage* storage) {
	if (storage) {
		r_id_pool_free (storage->pool);
		free (storage->data);
	}
	free (storage);
}
