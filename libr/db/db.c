#include "r_db.h"


R_API void r_db_init(struct r_db_t *db)
{
	memset(&db->blocks, '\0', sizeof(db->blocks));
	db->id_min = -1;
	db->id_max = -1;
}

R_API struct r_db_t *r_db_new()
{
	struct r_db_t *db = (struct r_db_t *)malloc(sizeof(struct r_db_t));
	r_db_init(db);
	return db;
}

R_API struct r_db_block_t *r_db_block_new()
{
	struct r_db_block_t *ptr = (struct r_db_block_t *)
		malloc(sizeof(struct r_db_block_t));
	ptr->data = NULL;
	memset(&ptr->childs, '\0', sizeof(ptr->childs));
	return ptr;
}

R_API int r_db_add_id(struct r_db_t *db, int off, int size)
{
	off &= 0xff;
	if (db->blocks[off])
		return R_FALSE;
	if (db->id_min==-1) {
		db->id_min = off;
		db->id_max = off;
	} else if (db->id_max < off)
		db->id_max = off;
	if (off < db->id_min)
		db->id_min = off;
	db->blocks[off] = r_db_block_new();
	db->blocks_sz[off] = size;
	return R_TRUE;
}


static int _r_db_add_internal(struct r_db_t *db, int key, void *b)
{
	int i, idx, len, size = db->blocks_sz[key];
	struct r_db_block_t *block = db->blocks[key];
	if (block == NULL) {
		block = r_db_block_new();
		db->blocks[key] = block;
	}
	for(i=0;i<size;i++) {
		idx = (((u8 *)b)[key+i]) & 0xff;
		if (block->childs[idx] == NULL)
			block->childs[idx] = r_db_block_new();
		block = block->childs[idx];
	}
	if (block) {
		if (block->data==NULL) {
			block->data = malloc(sizeof(void *)*2);
			block->data[0] = b;
			block->data[1] = NULL;
		} else {
			for(len=0;block->data[len];len++);
			block->data = realloc(block->data,
					sizeof(void *)*(len+1));
			block->data[len] = b;
			block->data[len+1] = NULL;
		}
	}
	return (block!=NULL);;
}

R_API int r_db_add(struct r_db_t *db, void *b)
{
	int i, ret=0;
	for(i=db->id_min;i<db->id_max;i++) {
		if (db->blocks[i])
			ret += _r_db_add_internal(db, i, b);
	}
	return ret;
}


R_API void *r_db_get(struct r_db_t *db, int key, const u8 *b)
{
	struct r_db_block_t *block;
	int i, size;
	if (key == -1) {
		for(i=0;i<R_DB_KEYS;i++) {
			if (db->blocks[i]) {
				key = i;
				break;
			}
		}
		if (key == -1)
			return NULL;
	}
	size = db->blocks_sz[key];
	block = db->blocks[key];
	for(i=0;block && i<size;i++)
		block = block->childs[b[key+i]];
	if (block)
		return block->data;
	return NULL;
}

R_API int r_db_delete(struct r_db_t *db, const u8 *b)
{
	void *ptr = r_db_get(db, -1, b);
	if (db->cb_free && ptr)
		return db->cb_free(db, ptr, db->cb_user);
	return (ptr != NULL);
}

R_API void *r_db_get_next(void *ptr)
{
	return (void *)*((int*)ptr+1);
}

R_API struct r_db_iter_t *r_db_iter(struct r_db_t *db, int key, const u8 *b)
{
	return NULL;
}

R_API void *r_db_iter_next(struct r_db_t *db, struct r_db_iter_t *iter)
{
	return NULL;
}

R_API void *r_db_iter_prev(struct r_db_t *db, struct r_db_iter_t *iter)
{
	return NULL;
}

R_API int r_db_free(struct r_db_t *db)
{
#if 0
	r_db_iter_t *iter = r_db_iter(db,-1);
	if (db->cb_free) {
		r_db_delete(db); // XXX
	}
#endif
	return 0;
}

/* stack ops */
#if 0
R_API int r_db_push(struct r_db_t *db, const u8 *b)
{
	return 0;
}

R_API const u8 *r_db_pop(struct r_db_t *db)
{
	return NULL;
}
#endif
