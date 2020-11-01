/* radare2 - LGPL - Copyright 2017-2020 - condret */

#include <r_util.h>
#include <r_types.h>
#include <string.h>
#include <stdlib.h>
#if __WINDOWS__
#include <search.h>
#endif

static ut32 get_msb(ut32 v) {
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
		if (pool) {
			pool->next_id = pool->start_id = start_id;
			pool->last_id = last_id;
		}
	}
	return pool;
}

R_API bool r_id_pool_grab_id(RIDPool* pool, ut32* grabber) {
	r_return_val_if_fail (pool && grabber, false);

	*grabber = UT32_MAX;
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
	RIDStorage* storage = NULL;
	RIDPool *pool = r_id_pool_new (start_id, last_id);
	if (pool) {
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

static bool oid_storage_preallocate(ROIDStorage *st, ut32 size) {
	ut32 *permutation;
	if (!st) {
		return false;
	}
	if (!size) {
		R_FREE (st->permutation);
		st->psize = 0;
	}
	permutation = realloc (st->permutation, size * sizeof (ut32));
	if (!permutation) {
		return false;
	}
	if (size > st->psize) {
		memset (permutation + st->psize, 0, (size - st->psize) * sizeof (ut32));
	}
	st->permutation = permutation;
	st->psize = size;
	return true;
}

R_API bool r_id_storage_set(RIDStorage* storage, void* data, ut32 id) {
	ut32 n;
	if (!storage || !storage->pool || (id >= storage->pool->next_id)) {
		return false;
	}
	n = get_msb (id + 1);
	if (n > ((storage->size / 2) + (storage->size / 4))) {
		if ((n * 2) < storage->pool->last_id) {
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

R_API bool r_id_storage_get_lowest(RIDStorage *storage, ut32 *id) {
	r_return_val_if_fail (storage, false);
	ut32 i;
	for (i = 0; i < storage->size && !storage->data[i]; i++);
	*id = i;
	return i < storage->size;
}

R_API bool r_id_storage_get_highest(RIDStorage *storage, ut32 *id) {
	r_return_val_if_fail (storage, false);
	size_t i = 0;
	if (storage->size > 0) {
		for (i = storage->size - 1; !storage->data[i] && i > 0; i--);
		*id = i;
		return storage->data[i] != NULL;
	}
	// *id = i;
	return false;
}

R_API bool r_id_storage_get_next(RIDStorage *storage, ut32 *idref) {
	r_return_val_if_fail (idref && storage, false);
	ut32 id = *idref;
	if (storage->size < 1 || id >= storage->size || !storage->data) {
		return false;
	}
	for (id = *idref + 1; id < storage->size && !storage->data[id]; id++);
	if (id < storage->size) {
		*idref = id;
		return true;
	}
	return false;
}

R_API bool r_id_storage_get_prev(RIDStorage *storage, ut32 *idref) {
	r_return_val_if_fail (idref && storage, false);
	ut32 id = *idref;
	if (id == 0 || id >= storage->size || storage->size < 1 || !storage->data) {
		return false;
	}
	for (id = *idref - 1; id > 0 && !storage->data[id]; id--);
	if (storage->data[id]) {
		*idref = id;
		return true;
	}
	return false;
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
			if (storage->data[storage->top_id]) {
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
		if (storage->data[i] && !cb (user, storage->data[i], i)) {
			return false;
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

static bool _list(void* user, void* data, ut32 id) {
	r_list_append (user, data);
	return true;
}

R_API RList *r_id_storage_list(RIDStorage *s) {		//remove this pls
	RList *list = r_list_newf (NULL);
	r_id_storage_foreach (s, _list, list);
	return list;
}

R_API ROIDStorage *r_oids_new(ut32 start_id, ut32 last_id) {
	ROIDStorage *storage = R_NEW0 (ROIDStorage);
	if (!storage) {
		return NULL;
	}
	if (!(storage->data = r_id_storage_new (start_id, last_id))) {
		free (storage);
		return NULL;
	}
	return storage;
}

R_API void *r_oids_get(ROIDStorage *storage, ut32 id) {
	if (storage) {
		return r_id_storage_get (storage->data, id);
	}
	return NULL;
}

R_API void *r_oids_oget(ROIDStorage *storage, ut32 od) {
	ut32 id;
	if (r_oids_get_id (storage, od, &id)) {
		return r_id_storage_get (storage->data, id);
	}
	return NULL;
}

R_API bool r_oids_get_id(ROIDStorage *storage, ut32 od, ut32 *id) {
	if (storage && storage->permutation && (storage->ptop > od)) {
		*id = storage->permutation[od];
		return true;
	}
	return false;
}

R_API bool r_oids_get_od(ROIDStorage *storage, ut32 id, ut32 *od) {
	if (storage && storage->permutation &&
		storage->data && (id < storage->data->pool->next_id)) {
		for (od[0] = 0; od[0] < storage->ptop; od[0]++) {
			if (id == storage->permutation[od[0]]) {
				return true;
			}
		}
	}
	return false;
}

R_API bool r_oids_add(ROIDStorage *storage, void *data, ut32 *id, ut32 *od) {
	if (!storage || !id || !od) {
		return false;
	}
	if (!r_id_storage_add (storage->data, data, id)) {
		return false;
	}
	if (!storage->permutation) {
		oid_storage_preallocate (storage, 4);
	} else if (storage->ptop > (storage->psize * 3 / 4)) {
		oid_storage_preallocate (storage, storage->psize * 2);
	}
	if (storage->psize <= storage->ptop) {
		r_id_storage_delete (storage->data, *id);
		return false;
	}
	if (!storage->permutation) {
		return false;
	}
	*od = storage->ptop;
	storage->permutation[*od] = *id;
	storage->ptop++;
	return true;
}

R_API bool r_oids_to_front(ROIDStorage *storage, const ut32 id) {
	ut32 od;
	if (!storage || !storage->permutation) {
		return false;
	}
	for (od = 0; od < storage->ptop; od++) {
		if (id == storage->permutation[od]) {
			break;
		}
	}
	if (od == storage->ptop) {
		return false;
	} else if (od == (storage->ptop - 1)) {
		return true;
	}
	memmove (&storage->permutation[od], &storage->permutation[od + 1],
		(storage->ptop - od - 1) * sizeof (ut32));
	storage->permutation[storage->ptop - 1]= id;
	return true;
}

R_API bool r_oids_to_rear(ROIDStorage *storage, ut32 id) {
	ut32 od;
	if (!storage || !storage->permutation ||
		!storage->data || (id >= storage->data->pool->next_id)) {
		return false;
	}
	bool found = false;
	for (od = 0; od < storage->ptop; od++) {
		if (id == storage->permutation[od]) {
			found = true;
			break;
		}
	}
	if (od == storage->ptop) {
		return false;
	}
	if (!found) {
		return true;
	}
	memmove (&storage->permutation[1], &storage->permutation[0], od * sizeof (ut32));
	storage->permutation[0] = id;
	return true;
}

R_API void r_oids_delete(ROIDStorage *storage, ut32 id) {
	if (!r_oids_to_front (storage, id)) {
		return;
	}
	r_id_storage_delete (storage->data, id);
	storage->ptop--;
	if (!storage->ptop) {
		R_FREE (storage->permutation);
		storage->psize = 0;
	} else if ((storage->ptop + 1) < (storage->psize / 4)) {
		oid_storage_preallocate (storage, storage->psize / 2);
	}
}

R_API void r_oids_odelete(ROIDStorage *st, ut32 od) {
	ut32 n;
	if (!st || !st->permutation || od >= st->ptop) {
		return;
	}
	n = st->ptop - od - 1;
	r_id_storage_delete (st->data, st->permutation[od]);
	memmove (&st->permutation[od], &st->permutation[od + 1], n * sizeof(ut32));
	st->ptop--;
	if (!st->ptop) {
		R_FREE (st->permutation);
		st->psize = 0;
	} else if ((st->ptop + 1) < (st->psize / 4)) {
		oid_storage_preallocate (st, st->psize / 2);
	}
}

R_API void *r_oids_take(ROIDStorage *storage, ut32 id) {
	r_return_val_if_fail (storage, NULL);
	void *ret = r_id_storage_get (storage->data, id);
	r_oids_delete (storage, id);
	return ret;
}

R_API void *r_oids_otake(ROIDStorage *st, ut32 od) {
	void *ret = r_oids_oget (st, od);
	r_oids_odelete (st, od);
	return ret;
}

R_API void r_oids_free(ROIDStorage *storage) {
	if (storage) {
		free (storage->permutation);
		r_id_storage_free (storage->data);
	}
	free (storage);
}

//returns the element with lowest order
R_API void *r_oids_last(ROIDStorage *storage) {
	if (storage && storage->data && storage->data->data
		&& storage->permutation) {
		return storage->data->data[storage->permutation[0]];
	}
	return NULL;
}

//return the element with highest order
R_API void *r_oids_first(ROIDStorage *storage) {
	if (storage && storage->data && storage->data->data
		&& storage->permutation) {
		return storage->data->data[storage->permutation[storage->ptop - 1]];
	}
	return NULL;
}

R_API bool r_oids_foreach (ROIDStorage *storage, RIDStorageForeachCb cb, void *user) {
	ut32 i;
	ut32 id;
	if (!cb || !storage || !storage->data || !storage->data->data
		|| !storage->permutation) {
		return false;
	}
	for (i = storage->ptop - 1; i != 0; i--) {
		id = storage->permutation[i];
		if (!cb (user, storage->data->data[id], id)) {
			return false;
		}
	}
	id = storage->permutation[0];
	return cb (user, storage->data->data[id], id);
}

R_API bool r_oids_foreach_prev (ROIDStorage* storage, RIDStorageForeachCb cb, void* user) {
	ut32 i;
	ut32 id;
	if (!cb || !storage || !storage->data || !storage->data->data
		|| !storage->permutation) {
		return false;
	}
	for (i = 0; i < storage->ptop; i++) {
		id = storage->permutation[i];
		if (!cb (user, storage->data->data[id], id)) {
			return false;
		}
	}
	return true;
}

bool oids_od_bfind (ROIDStorage *st, ut32 *od, void *incoming, void *user) {
	st64 high, low;
	int cmp_res;
	void *in;

	if (!st->ptop) {
		return false;
	}

	high = st->ptop - 1;
	low = 0;

	while (1) {
		if (high <= low) {
			od[0] = (ut32)low;
			in = r_oids_oget(st, od[0]);
			//in - incoming
			if (!st->cmp(in, incoming, user, &cmp_res)) {
				return false;
			}
			if (cmp_res < 0) {
				od[0]++;
			}
			return true;
		}

		od[0] = (ut32)((low + high) / 2);
		in = r_oids_oget(st, od[0]);
		if (!st->cmp(in, incoming, user, &cmp_res)) {
			return false;
		}

		if (cmp_res == 0) {
			return true;
		}

		if (cmp_res < 0) {
			low = od[0] + 1;
		} else {
			high = od[0];
			high--;
		}
	}
	return false;
}

bool oids_od_binsert(ROIDStorage *storage, ut32 id, ut32 *od, void *incoming, void *user) {
	if (!oids_od_bfind (storage, od, incoming, user)) {
		return false;
	}
	if(od[0] != storage->ptop) {
		memmove (&storage->permutation[od[0] + 1], &storage->permutation[od[0]], (storage->ptop - od[0]) * sizeof(ut32));
	}
	storage->ptop++;
	storage->permutation[od[0]] = id;
	return true;
}

R_API bool r_oids_insert(ROIDStorage *storage, void *data, ut32 *id, ut32 *od, void *user) {
	if (!storage || !storage->cmp || !id || !od) {
		return false;
	}
	if (!storage->ptop) { //empty storage
		return r_oids_add (storage, data, id, od);
	}
	if (!r_id_storage_add (storage->data, data, id)) {
		return false;
	}
	if (storage->ptop > (storage->psize * 3 / 4)) {
		oid_storage_preallocate (storage, storage->psize * 2);
	}
	return oids_od_binsert (storage, id[0], od, data, user);
}

R_API bool r_oids_sort(ROIDStorage *storage, void *user) {
	ut32 od, id, ptop, *permutation;

	if (!storage || !storage->ptop || !storage->cmp) {
		return false;
	}
	if (storage->ptop == 1) {
		return true;
	}
	permutation = storage->permutation;
	storage->permutation = R_NEWS0 (ut32, storage->psize);
	if (!storage->permutation) {
		storage->permutation = permutation;
		return false;
	}
	storage->permutation[0] = permutation[0];
	ptop = storage->ptop;
	storage->ptop = 1;
	while (storage->ptop != ptop) {
		id = permutation[storage->ptop];
		void *incoming = r_id_storage_get (storage->data, id);
		if (!oids_od_binsert (storage, id, &od, incoming, user)) {
			goto beach;
		}
	}
	free (permutation);
	return true;

beach:
	free (storage->permutation);
	storage->permutation = permutation;
	storage->ptop = ptop;
	return false;
}

R_API ut32 r_oids_find(ROIDStorage *storage, void *incoming, void *user) {
	ut32 ret;
	return oids_od_bfind (storage, &ret, incoming, user) ? ret : storage->ptop;
}
