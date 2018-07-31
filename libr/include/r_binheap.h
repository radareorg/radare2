#ifndef R2_BINHEAP_H
#define R2_BINHEAP_H

#include "r_vector.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_binheap_t {
	RVector a;
	RVectorComparator cmp;
} RBinHeap;

R_API void r_binheap_clear(RBinHeap *h, void (*elem_free)(void *));
#define r_binheap_empty(h) (!(h)->a.len)
R_API void r_binheap_init(RBinHeap *h, RVectorComparator cmp);
R_API RBinHeap *r_binheap_new(RVectorComparator cmp);
R_API bool r_binheap_push(RBinHeap *h, void *x);
R_API void *r_binheap_pop(RBinHeap *h);
#define r_binheap_top(h) ((h)->a.a[0])

#ifdef __cplusplus
}
#endif

#endif
