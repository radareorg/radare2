/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_util.h>
#include <stdlib.h>

#define ALLOC_POOL_SIZE 1024
#define ALLOC_POOL_COUNT 128

// TODO: add api to serialize/deserialize memory pools from/to disk
// This can be useful when the application is swapping (userland swapping?)
// Do user-swapping takes sense?

R_API RMemoryPool* r_mem_pool_deinit(RMemoryPool *pool) {
	int i;
	for (i=0; i<pool->npool; i++)
		free (pool->nodes[i]);
	free (pool->nodes);
	pool->nodes = NULL;
	return pool;
}

R_API RMemoryPool *r_mem_pool_new(int nodesize, int poolsize, int poolcount) {
	RMemoryPool *mp;
	
	mp = R_NEW (RMemoryPool);
	if (mp) {
		if (poolsize<1)
			poolsize = ALLOC_POOL_SIZE;
		if (poolcount<1)
			poolcount = ALLOC_POOL_COUNT;
		// TODO: assert nodesize?;
		mp->poolsize = poolsize;
		mp->poolcount = poolcount;
		mp->nodesize = nodesize;
		mp->npool = -1;
		mp->ncount = mp->poolsize; // force init
		mp->nodes = (ut8**) malloc (sizeof (void*) * mp->poolcount);
		if (mp->nodes == NULL)
			return NULL;
	}
	return mp;
}

R_API RMemoryPool *r_mem_pool_free(RMemoryPool *pool) {
	r_mem_pool_deinit (pool);
	free (pool);
	return NULL;
}

R_API void* r_mem_pool_alloc(RMemoryPool *pool) {
	if (pool->ncount >= pool->poolsize) {
		if (++pool->npool >= pool->poolcount) {
			eprintf ("FAIL: Cannot allocate more memory in the pool\n");
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
