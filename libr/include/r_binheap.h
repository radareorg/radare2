#ifndef R2_BINHEAP_H
#define R2_BINHEAP_H

#include "r_vector.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_binheap_t {
	RPVector a;
	RPVectorComparator cmp;
} RBinHeap;

R_API void r_binheap_clear(RBinHeap *h);
#define r_binheap_empty(h) (r_pvector_empty (&(h)->a))
R_API void r_binheap_init(RBinHeap *h, RPVectorComparator cmp);
R_API RBinHeap *r_binheap_new(RPVectorComparator cmp);
R_API bool r_binheap_push(RBinHeap *h, void *x);
R_API void *r_binheap_pop(RBinHeap *h);
#define r_binheap_top(h) (r_pvector_at(&((h)->a), 0))

#ifdef __cplusplus
}
#endif

#endif
