#ifndef R_POOL_H
#define R_POOL_H
#include <r_util/r_mem.h>

typedef struct r_mem_pool_factory_t {
	int limit;
	RMemoryPool **pools;
} RPoolFactory;

R_API RPoolFactory *r_poolfactory_instance(void);
R_API void r_poolfactory_init (int limit);
R_API RPoolFactory* r_poolfactory_new(int limit);
R_API void *r_poolfactory_alloc(RPoolFactory *pf, int nodesize);
R_API void r_poolfactory_stats(RPoolFactory *pf);
R_API void r_poolfactory_free(RPoolFactory *pf);
#endif //  R_POOL_H
