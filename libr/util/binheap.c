#include "r_binheap.h"

static inline void _heap_down(RBinHeap *h, int i, void *x) {
	int j;
	for (; j = i * 2 + 1, j < h->a.len; i = j) {
		if (j + 1 < h->a.len && h->cmp (h->a.a[j+1], h->a.a[j])) {
			j++;
		}
		if (!(h->cmp (h->a.a[j], x))) {
			break;
		}
		h->a.a[i] = h->a.a[j];
	}
	h->a.a[i] = x;
}

static inline void _heap_up(RBinHeap *h, int i, void *x) {
	int j;
	for (; i && (j = (i-1) >> 1, h->cmp (x, h->a.a[j])); i = j) {
		h->a.a[i] = h->a.a[j];
	}
	h->a.a[i] = x;
}

R_API void r_binheap_clear(RBinHeap *h, void (*elem_free)(void *)) {
  r_vector_clear (&h->a, elem_free);
}

R_API void r_binheap_init(RBinHeap *h, RVectorComparator cmp) {
	r_vector_init (&h->a);
	h->cmp = cmp;
}

R_API RBinHeap *r_binheap_new(RVectorComparator cmp) {
	RBinHeap *h = R_NEW (RBinHeap);
	if (h) {
		h->cmp = cmp;
	}
	return h;
}

R_API void *r_binheap_pop(RBinHeap *h) {
	void *ret = h->a.a[0];
	h->a.len--;
	_heap_down (h, 0, h->a.a[h->a.len]);
	return ret;
}

R_API bool r_binheap_push(RBinHeap *h, void *x) {
	if (!r_vector_push (&h->a, NULL)) {
		return false;
	}
	_heap_up (h, h->a.len - 1, x);
	return true;
}
