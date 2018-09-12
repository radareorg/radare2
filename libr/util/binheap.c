#include "r_binheap.h"

static inline void _heap_down(RBinHeap *h, size_t i, void *x) {
	size_t j;
	for (; j = i * 2 + 1, j < h->a.v.len; i = j) {
		if (j + 1 < h->a.v.len && h->cmp (r_pvec_at (&h->a, j+1), r_pvec_at (&h->a, j)) < 0) {
			j++;
		}
		if (h->cmp (r_pvec_at (&h->a, j), x) >= 0) {
			break;
		}
		r_pvec_set (&h->a, i, r_pvec_at (&h->a, j));
	}
	r_pvec_set (&h->a, i, x);
}

static inline void _heap_up(RBinHeap *h, size_t i, void *x) {
	size_t j;
	for (; i && (j = (i-1) >> 1, h->cmp (x, r_pvec_at (&h->a, j)) < 0); i = j) {
		r_pvec_set (&h->a, i, r_pvec_at (&h->a, j));
	}
	r_pvec_set (&h->a, i, x);
}

R_API void r_binheap_clear(RBinHeap *h) {
  r_pvec_clear (&h->a);
}

R_API void r_binheap_init(RBinHeap *h, RPVecComparator cmp) {
	r_pvec_init (&h->a, NULL);
	h->cmp = cmp;
}

R_API RBinHeap *r_binheap_new(RPVecComparator cmp) {
	RBinHeap *h = R_NEW (RBinHeap);
	if (!h) {
		return NULL;
	}
	r_pvec_init (&h->a, NULL);
	h->cmp = cmp;
	return h;
}

R_API void *r_binheap_pop(RBinHeap *h) {
	void *ret = r_pvec_at (&h->a, 0);
	h->a.v.len--;
	_heap_down (h, 0, r_pvec_at (&h->a, h->a.v.len));
	return ret;
}

R_API bool r_binheap_push(RBinHeap *h, void *x) {
	if (!r_pvec_push (&h->a, NULL)) {
		return false;
	}
	_heap_up (h, h->a.v.len - 1, x);
	return true;
}
