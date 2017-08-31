/* radare2 - LGPL - Copyright 2017 - condret */

#include <r_util.h>
#include <r_types.h>
#include <string.h>

ut32 get_msb(ut32 v) {
	int i;
	for (i = 31; i > (-1); i--) {
		if (v & (0x1U << i)) {
			return (v & (0x1U << i));
		}
	}
	return 0;
}

static int _insert_cmp (void *_incoming, void *_in, void *user) {
	ut32 incoming = (ut32)(size_t)_incoming;
	ut32 in = (ut32)(size_t)_in;
//	eprintf ("incoming %d\tin %d\n", incoming, in);
	return incoming - in;
}

static int _del_cmp (void *_incoming, void *_in, void *user) {
	ut32 incoming = (ut32)(size_t)_incoming;
	ut32 in = (ut32)(size_t)_in;
//	eprintf ("incoming %d\tin %d\n", incoming, in);
	if (incoming >= in) {
		return 0;
	}
	return incoming - in;
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
		RBTreeIter iter = r_rbtree_first (pool->freed_ids);
		*grabber = (ut32)(size_t)(iter.path[iter.len-1]->data);
//		eprintf ("deleting %d from the tree\n", *grabber);
		r_rbtree_delete (pool->freed_ids, (void *)(size_t)(*grabber), NULL);
		if (r_rbtree_size (pool->freed_ids) == 1) {
			r_rbtree_free (pool->freed_ids);
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
		if (pool->freed_ids) {
			RBTreeIter iter = r_rbtree_last (pool->freed_ids);
			while ((iter.len) && ((pool->next_id - 1) <= (ut32)(size_t)(iter.path[iter.len-1]->data))) {
//				eprintf ("element in tree %d\n", (ut32)(size_t)(iter.path[iter.len-1]->data));
				pool->next_id--;
				r_rbtree_iter_prev (&iter);
			}
			pool->freed_ids->cmp = (RBTreeComparator)_del_cmp;
			while (r_rbtree_delete (pool->freed_ids, (void *)(size_t)(pool->next_id - 1), NULL)) {}
			if (r_rbtree_size (pool->freed_ids) == 1) {
				r_rbtree_free (pool->freed_ids);
				pool->freed_ids = NULL;
			} else {
				pool->freed_ids->cmp = (RBTreeComparator)_insert_cmp;
			}
		}
		return true;
	}
	if (!pool->freed_ids) {
		pool->freed_ids = r_rbtree_new (NULL, (RBTreeComparator)_insert_cmp);
	}
	r_rbtree_insert (pool->freed_ids, (void*)(size_t)kick, NULL);
	return true;
}

R_API void r_id_pool_free(RIDPool* pool) {
	if (pool && pool->freed_ids) {
		r_rbtree_free (pool->freed_ids);
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
	void* data;
	if (!storage) {
		return false;
	}
	if (storage->size == size) {
		return true;
	}
	if (storage->size > size) {
		storage->data = realloc (storage->data, size * sizeof(void*));
		storage->size = size;
		return true;
	}
	data = storage->data;
	storage->data = R_NEWS0 (void*, size);
	if (data) {
		memcpy (storage->data, data, storage->size * sizeof(void*));
	}
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

R_API ROIDStorage * r_oid_storage_new (ut32 start_id, ut32 last_id) {
	ROIDStorage *storage = R_NEW0 (ROIDStorage);
	if (!storage) {
		return NULL;
	}
	if (!(storage->permutation = r_id_storage_new (0, last_id))) {
		free (storage);
		return NULL;
	}
	if (!(storage->data = r_id_storage_new (start_id, last_id))) {
		r_id_storage_free (storage->permutation);
		free (storage);
		return NULL;
	}
	return storage;
}

R_API void *r_oid_storage_get(ROIDStorage *storage, ut32 id) {
	if (storage) {
		return r_id_storage_get (storage->data, id);
	}
	return NULL;
}

R_API void *r_oid_storage_oget(ROIDStorage *storage, ut32 od) {
	ut32 id;
	if (r_oid_storage_get_id (storage, od, &id)) {
		return r_id_storage_get (storage->data, id);
	}
	return r_id_storage_get (storage->data, id);
}

R_API bool r_oid_storage_get_id(ROIDStorage *storage, ut32 od, ut32 *id) {
	if (storage && storage->permutation && (od < storage->permutation->pool->next_id)) {
		*id = (ut32)(size_t)storage->permutation->data[od];
		return true;
	}
	return false;
}

R_API bool r_oid_storage_get_od(ROIDStorage *storage, ut32 id, ut32 *od) {
	if (storage && storage->permutation &&
		storage->data && (id < storage->data->pool->next_id)) {
		for (*od = 0; *od < storage->permutation->pool->next_id; *od++) {
			if (id == (ut32)(size_t)storage->permutation->data[*od]) {
				return true;
			}
		}
	}
	return false;
}

R_API bool r_oid_storage_add(ROIDStorage *storage, void *data, ut32 *id, ut32 *od) {
	if (!storage || !id || !od) {
		return false;
	}
	if (!r_id_storage_add (storage->data, data, id)) {
		return false;
	}
	if (!r_id_storage_add (storage->permutation, (void *)(size_t)id, od)) {
		r_id_storage_delete (storage->data, id);
		return false;
	}
	return true;
}

R_API bool r_oid_storage_to_front (ROIDStorage *storage, ut32 id) {
	ut32 od;
	if (!r_oid_storage_get_od (storage, id, &od)) {
		return false;
	}
	if (od == (storage->permutation->pool->next_id - 1)) {
		return true;
	}
	memmove (&storage->permutation->data[od], &storage->permutation->data[od + 1],
		(storage->permutation->pool->next_id - (od + 1)) * sizeof(void *));
	storage->permutation->data[storage->permutation->pool->next_id - 1] =
		(void *)(size_t)id;
	return true;
}

R_API void r_oid_storage_delete(ROIDStorage *storage, ut32 id) {
	if (!r_oid_storage_to_front (storage, id)) {
		return;
	}
	r_id_storage_delete (storage->permutation, storage->permutation->pool->next_id - 1);
	r_id_storage_delete (storage->data, id);
}

R_API void *r_oid_storage_take (ROIDStorage *storage, ut32 id) {
	void *ret;
	if (!storage) {
		return NULL;
	}
	ret = r_id_storage_get (storage->data, id);
	r_oid_storage_delete (storage, id);
	return ret;
}

R_API void r_oid_storage_free (ROIDStorage *storage) {
	if (storage) {
		r_id_storage_free (storage->permutation);
		r_id_storage_free (storage->data);
	}
	free (storage);
}
