/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_util.h>
#include <stdlib.h>

#define ALLOC_POOL_SIZE 1024
#define ALLOC_POOL_COUNT 128

// TODO: add api to serialize/deserialize memory pools from/to disk
// This can be useful when the application is swapping (userland swapping?)
// Do user-swapping takes sense?

R_API struct r_mem_pool_t* r_mem_pool_deinit(struct r_mem_pool_t *pool)
{
	int i;
	for(i=0;i<pool->npool;i++)
		free(pool->nodes[i]);
	free(pool->nodes);
	pool->nodes = NULL;
	return pool;
}

R_API struct r_mem_pool_t* r_mem_pool_init(struct r_mem_pool_t *pool, int nodesize, int poolsize, int poolcount)
{
	if (pool) {
		if (poolsize < 1) poolsize = ALLOC_POOL_SIZE;
		if (poolcount < 1) poolcount = ALLOC_POOL_COUNT;
		// TODO: assert nodesize?;
		pool->poolsize = poolsize;
		pool->poolcount = poolcount;
		pool->nodesize = nodesize;
		pool->npool = -1;
		pool->ncount = pool->poolsize; // force init
		pool->nodes = (void**) malloc(sizeof(void*)*pool->poolcount);
	}
	return pool;
}

R_API struct r_mem_pool_t *r_mem_pool_new(int nodesize, int poolsize, int poolcount)
{
	return r_mem_pool_init(MALLOC_STRUCT(struct r_mem_pool_t),
		nodesize, poolsize, poolcount);
}

R_API struct r_mem_pool_t *r_mem_pool_free(struct r_mem_pool_t *pool)
{
	return (r_mem_pool_deinit(pool),free(pool),NULL);
}

R_API void* r_mem_pool_alloc(struct r_mem_pool_t *pool)
{
	if (pool->ncount >= pool->poolsize) {
		if (++pool->npool >= pool->poolcount) {
			fprintf (stderr, "FAIL: Cannot allocate more memory in the pool\n");
			return NULL;
		}
		pool->nodes[pool->npool] = malloc (pool->nodesize*pool->poolsize);
		if (pool->nodes[pool->npool] == NULL)
			return NULL;
		pool->ncount = 0;
	}
	// TODO: fix warning
	return (void *)(&(pool->nodes[pool->npool][pool->ncount++]));
}

//does not yet supports arguments R_DEFINE_OBJECT(r_mem_pool);
