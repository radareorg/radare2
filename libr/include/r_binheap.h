#ifndef R2_BINHEAP_H
#define R2_BINHEAP_H

#include "r_vec.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_binheap_t {
	RPVec a;
	RPVecComparator cmp;
} RBinHeap;

R_API void r_binheap_clear(RBinHeap *h);
#define r_binheap_empty(h) (r_pvec_empty (&(h)->a))
R_API void r_binheap_init(RBinHeap *h, RPVecComparator cmp);
R_API RBinHeap *r_binheap_new(RPVecComparator cmp);
R_API bool r_binheap_push(RBinHeap *h, void *x);
R_API void *r_binheap_pop(RBinHeap *h);
#define r_binheap_top(h) (r_pvec_at(&((h)->a), 0))

#ifdef __cplusplus
}
#endif

#endif
