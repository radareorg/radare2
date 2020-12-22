/* radare2 - LGPL - Copyright 2017-2018 - maskray */

#include "r_binheap.h"

static inline void _heap_down(RBinHeap *h, size_t i, void *x) {
	size_t j;
	for (; j = i * 2 + 1, j < h->a.v.len; i = j) {
		if (j + 1 < h->a.v.len && h->cmp (r_pvector_at (&h->a, j+1), r_pvector_at (&h->a, j)) < 0) {
			j++;
		}
		if (h->cmp (r_pvector_at (&h->a, j), x) >= 0) {
			break;
		}
		r_pvector_set (&h->a, i, r_pvector_at (&h->a, j));
	}
	if (i < h->a.v.len) {
		r_pvector_set (&h->a, i, x);
	}
}

static inline void _heap_up(RBinHeap *h, size_t i, void *x) {
	size_t j;
	for (; i && (j = (i-1) >> 1, h->cmp (x, r_pvector_at (&h->a, j)) < 0); i = j) {
		r_pvector_set (&h->a, i, r_pvector_at (&h->a, j));
	}
	r_pvector_set (&h->a, i, x);
}

R_API void r_binheap_clear(RBinHeap *h) {
	r_pvector_clear (&h->a);
}

R_API void r_binheap_init(RBinHeap *h, RPVectorComparator cmp) {
	r_pvector_init (&h->a, NULL);
	h->cmp = cmp;
}

R_API void r_binheap_free(RBinHeap *h) {
	r_binheap_clear (h);
	free (h);
}

R_API RBinHeap *r_binheap_new(RPVectorComparator cmp) {
	RBinHeap *h = R_NEW (RBinHeap);
	if (!h) {
		return NULL;
	}
	r_pvector_init (&h->a, NULL);
	h->cmp = cmp;
	return h;
}

R_API void *r_binheap_pop(RBinHeap *h) {
	void *ret = r_pvector_at (&h->a, 0);
	_heap_down (h, 0, r_pvector_pop (&h->a));
	return ret;
}

R_API bool r_binheap_push(RBinHeap *h, void *x) {
	if (!r_pvector_push (&h->a, NULL)) {
		return false;
	}
	_heap_up (h, h->a.v.len - 1, x);
	return true;
}
