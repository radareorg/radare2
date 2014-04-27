/* radare - LGPL - Copyright 2009-2013 - pancake */

#include "r_db.h"

R_LIB_VERSION (r_db);
#if 0
Configurable options:
 - allow dupped nodes? (two times the same pointer?)
#endif

R_API RDatabase *r_db_new() {
	RDatabase *db = R_NEW (RDatabase);
	if (db) {
		memset (&db->blocks, '\0', sizeof (db->blocks));
		db->id_min = -1;
		db->id_max = -1;
	}
	return db;
}

R_API RDatabaseBlock *r_db_block_new() {
	RDatabaseBlock *ptr = R_NEW0 (RDatabaseBlock);
	return ptr;
}

R_API int r_db_add_id(struct r_db_t *db, int key, int size) {
	key &= 0xff;
	if (db->blocks[key])
		return R_FALSE;
	if (db->id_min==-1) {
		db->id_min = key;
		db->id_max = key;
	} else if (db->id_max < key)
		db->id_max = key;
	if (key < db->id_min)
		db->id_min = key;
	db->blocks[key] = r_db_block_new ();
	db->blocks_sz[key] = size;
	return R_TRUE;
}

static int _r_db_add_internal(struct r_db_t *db, int key, void *b) {
	int i, idx, len, size;
	struct r_db_block_t *block;
	if (key<0 || key>255)
		return R_FALSE;
	size = db->blocks_sz[key];
	block = db->blocks[key];
	if (block == NULL) {
		block = r_db_block_new ();
		db->blocks[key] = block;
	}
	for (i=0;i<size;i++) {
		idx = (((ut8 *)b)[key+i]) & 0xff;
		if (block->childs[idx] == NULL)
			block->childs[idx] = r_db_block_new();
		block = block->childs[idx];
	}
	if (block) {
		if (block->data == NULL) {
			// TODO: use slices.. much faster alloc+free
			block->data = malloc(sizeof(void *)*2);
			block->data[0] = b;
			block->data[1] = NULL;
		} else {
			for (len=0; block->data[len]; len++);
			block->data = realloc (block->data, sizeof (void *)*(len+2));
			block->data[len] = b;
			block->data[len+1] = NULL;
		}
	}
	return (block != NULL);
}

R_API int r_db_add(struct r_db_t *db, void *b) {
	int i, ret = R_FALSE;
	for (i=db->id_min;i<=db->id_max;i++)
		if (db->blocks[i])
			ret += _r_db_add_internal (db, i, b);
	return ret;
}

R_API int r_db_add_unique(struct r_db_t *db, void *b) {
	int i, ret = R_TRUE;
	for(i=db->id_min;i<=db->id_max;i++) {
		if (db->blocks[i] && r_db_get (db, i, b) != NULL) {
			ret = R_FALSE;
			break;
		}
	}
	if (ret) ret = r_db_add (db, b);
	return ret;
}

R_API void **r_db_get(struct r_db_t *db, int key, const ut8 *b) {
	RDatabaseBlock *block;
	int i, size;
	if (key == -1) {
		key = db->id_min;
#if 0
UNNECESSARY LOOPZ
		for (i=0;i<R_DB_KEYS;i++) {
			if (db->blocks[i]) {
				key = i;
				break;
			}
		}
		if (key == -1)
			return NULL;
#endif
	}
	size = db->blocks_sz[key];
	block = db->blocks[key];
	for (i=0; block && i<size; i++)
		block = block->childs[b[key+i]];
	if (block)
		return block->data;
	return NULL;
}

/* TODO: MOVE AS DEFINE IN r_db.h */
R_API void **r_db_get_next(void **ptr) {
	return ptr+1;
}

/* TODO: MOVE AS DEFINE IN r_db.h */
R_API void *r_db_get_cur(void **ptr) {
	return ptr[0];
}

static int _r_db_delete_internal(struct r_db_t *db, int key, const ut8 *b) {
	RDatabaseBlock *block;
	int i, j, size = db->blocks_sz[key];
	block = db->blocks[key];

	for (i=0;block&&i<size;i++)
		block = block->childs[b[key+i]];

	if (block && block->data) {
		for (i=0;block->data[i]; i++) {
			if (block->data[i] == b)
				for (j=i;block->data[j]; j++)
					block->data[j] = block->data[j+1];
		}
		if (block->data[0] == NULL) {
			free (block->data);
			block->data = NULL;
		}
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_db_delete(struct r_db_t *db, const void *ptr) {
	int i;
	for (i=db->id_min; i<=db->id_max; i++)
		if (db->blocks[i])
			if (!_r_db_delete_internal (db, i, ptr))
				eprintf ("failed to delete internal pointer\n");
	/* TODO */
	if (db->cb_free && ptr)
		return db->cb_free (db, ptr, db->cb_user);
	return (ptr != NULL);
}

static int r_db_iter_find_next(RDatabaseIter *it) {
	// TODO
	return R_FALSE;
}

R_API RDatabaseIter *r_db_iter_new(RDatabase *db, int key) {
	RDatabaseIter *iter = R_NEW (RDatabaseIter);
	/* TODO: detect when keys are not valid and return NULL */
	iter->db = db;
	iter->key = key;
	iter->size = db->blocks_sz[key];
	memset (&iter->path, 0, sizeof (iter->path));
	/* TODO: detect when no keys are found and return NULL */
	iter->ptr = 0;
	iter->cur = NULL;
	r_db_iter_find_next (iter);
	/* TODO: first iteration must be done here */
	return iter;
}

R_API void *r_db_iter_cur(struct r_db_iter_t *iter) {
	return iter->cur;
#if 0
	void *cur = NULL;
	int i, depth = 0;
	struct r_db_t *db = iter->db;
	struct r_db_block_t *b = db->blocks[iter->key];
	if (iter->ptr == 0) {
		/* first iteration */
	} else {
		for(i=0;i<iter->size;i++) {
			b = &b[iter->path[i]];
			if (b == NULL) {
				fprintf(stderr, "r_db: Internal data corruption\n");
				return NULL;
			}
		}
		/* TODO: check if null to find next node */
		return b->data[iter->ptr];
	}

	for(i=0;i<255;i++) {
		if (b->childs[i]) {
			/* walk childs until reaching the leafs */
			b = b->childs[i];
			i=0;
			depth++;
			if (depth == iter->size) {
				break;
			}
			continue;
		}
	}
	//iter->db
	return cur;
#endif
}

// NOTE: required for vala/swig
R_API void *r_db_iterator(RDatabase *db) {
	return r_db_iter_new (db, db->id_min);
}

/* returns 1 if there is a next element */
R_API int r_db_iter_next(RDatabaseIter *iter) {
	//RDatabaseBlock *b, *block;
	int i;//, j;
// TODO: must be implemented for Vala/Swig
	// if (something) return 1;
	// depth = iter->size
	// 
	for (i=iter->ptr; i<iter->size; i++) {
		//block = block->childs[b[key+i]];
	}
	iter->ptr = i; // update pointer
	iter->cur = NULL;
	return 0;
}

/* return current iter data and go to next iterable element */
R_API void *r_db_iter_get(RDatabaseIter *iter) {
	void *data = iter->cur;
	
// TODO: must be implemented for Vala/Swig
	return data;
}

R_API void *r_db_iter_prev(struct r_db_iter_t *iter) {
	/* TODO */
	return NULL;
}

R_API struct r_db_iter_t *r_db_iter_free(struct r_db_iter_t *iter) {
	free (iter);
	return NULL;
}

R_API int r_db_free(struct r_db_t *db) {
	/* TODO : using the iterator logic */
	// TODO: use r_pool_mem here!
#if 0
	r_db_iter_t *iter = r_db_iter(db, -1);
	if (db->cb_free) {
		r_db_delete(db); // XXX
	}
#endif
	return 0;
}
