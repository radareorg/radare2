#include "r_vector.h"

// Optimize memory usage on glibc
#if __WORDSIZE == 32
// Chunk size 24, minus 4 (chunk header), minus 8 for capacity and len, 12 bytes remaining for 3 void *
#define INITIAL_VECTOR_LEN 3
#else
// For __WORDSIZE == 64
// Chunk size 48, minus 8 (chunk header), minus 8 for capacity and len, 32 bytes remaining for 4 void *
#define INITIAL_VECTOR_LEN 4
#endif

#define NEXT_VECTOR_CAPACITY (vec->capacity < INITIAL_VECTOR_LEN \
	? INITIAL_VECTOR_LEN \
	: vec->capacity <= 12 ? vec->capacity * 2 \
	: vec->capacity + (vec->capacity >> 1))

#define RESIZE_OR_RETURN_NULL(next_capacity) do { \
		size_t new_capacity = next_capacity; \
		void **new_a = realloc (vec->a, vec->elem_size * new_capacity); \
		if (!new_a) { \
			return NULL; \
		} \
		vec->a = new_a; \
		vec->capacity = new_capacity; \
	} while (0)
		
		

R_API void r_vector_init(RVector *vec, size_t elem_size, RVectorFree free, void *free_user) {
	vec->a = NULL;
	vec->capacity = vec->len = 0;
	vec->elem_size = elem_size;
	vec->free = free;
	vec->free_user = free_user;
}

R_API RVector *r_vector_new(size_t elem_size, RVectorFree free, void *free_user) {
	RVector *vec = R_NEW (RVector);
	if (!vec) {
		return NULL;
	}
	r_vector_init (vec, elem_size, free, free_user);
	return vec;
}

static void vector_free_elems(RVector *vec) {
	if (vec->free) {
		while (vec->len > 0) {
			vec->free (r_vector_index_ptr (vec, --vec->len), vec->free_user);
		}
	} else {
		vec->len = 0;
	}
}

R_API void r_vector_clear(RVector *vec) {
	vector_free_elems (vec);
	R_FREE (vec->a);
	vec->capacity = 0;
}

R_API void r_vector_free(RVector *vec) {
	vector_free_elems (vec);
	free (vec->a);
	free (vec);
}

static bool vector_clone(RVector *dst, RVector *src) {
	dst->capacity = src->capacity;
	dst->len = src->len;
	dst->elem_size = src->elem_size;
	dst->free = src->free;
	dst->free_user = src->free_user;
	if (!dst->len) {
		dst->a = NULL;
	} else {
		dst->a = malloc (src->elem_size * src->capacity);
		if (!dst->a) {
			return false;
		}
		memcpy (dst->a, src->a, src->elem_size * src->len);
	}
	return true;
}

R_API RVector *r_vector_clone(RVector *vec) {
	RVector *ret = R_NEW (RVector);
	if (!ret) {
		return NULL;
	}
	if (!vector_clone (ret, vec)) {
		free (ret);
		return NULL;
	}
	return ret;
}



R_API void *r_vector_index_ptr(RVector *vec, size_t index) {
	return (char *)vec->a + vec->elem_size * index;
}

R_API void r_vector_assign(RVector *vec, void *p, void *elem) {
	memcpy (p, elem, vec->elem_size);
}

R_API void *r_vector_assign_at(RVector *vec, size_t index, void *elem) {
	void *p = r_vector_index_ptr (vec, index);
	if (elem) {
		r_vector_assign (vec, p, elem);
	}
	return p;
}

R_API void r_vector_remove_at(RVector *vec, size_t index, void *into) {
	void *p = r_vector_index_ptr (vec, index);
	if (into) {
		r_vector_assign (vec, into, p);
	}
	vec->len--;
	if (index < vec->len) {
		memmove (p, (char *)p + vec->elem_size, vec->elem_size * (vec->len - index));
	}
}



R_API void *r_vector_insert(RVector *vec, size_t index, void *x) {
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL (NEXT_VECTOR_CAPACITY);
	}
	void *p = r_vector_index_ptr (vec, index);
	if (index < vec->len) {
		memmove ((char *)p + vec->elem_size, p, vec->elem_size * (vec->len - index));
	}
	vec->len++;
	if (x) {
		r_vector_assign (vec, p, x);
	}
	return p;
}

R_API void *r_vector_insert_range(RVector *vec, size_t index, void *first, size_t count) {
	if (vec->len + count > vec->capacity) {
		RESIZE_OR_RETURN_NULL (R_MAX (NEXT_VECTOR_CAPACITY, vec->len + count));
	}
	size_t sz = count * vec->elem_size;
	void *p = r_vector_index_ptr (vec, index);
	if (index < vec->len) {
		memmove ((char *)p + sz, p, vec->elem_size * (vec->len - index));
	}
	vec->len += count;
	if (first) {
		memcpy (p, first, sz);
	}
	return p;
}

R_API void r_vector_pop(RVector *vec, void *into) {
	if (into) {
		r_vector_assign (vec, into, r_vector_index_ptr (vec, vec->len - 1));
	}
	vec->len--;
}

R_API void r_vector_pop_front(RVector *vec, void *into) {
	r_vector_remove_at (vec, 0, into);
}

R_API void *r_vector_push(RVector *vec, void *x) {
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL (NEXT_VECTOR_CAPACITY);
	}
	void *p = r_vector_index_ptr (vec, vec->len++);
	if (x) {
		r_vector_assign (vec, p, x);
	}
	return p;
}

R_API void *r_vector_push_front(RVector *vec, void *x) {
	return r_vector_insert (vec, 0, x);
}

R_API void *r_vector_reserve(RVector *vec, size_t capacity) {
	if (vec->capacity < capacity) {
		RESIZE_OR_RETURN_NULL (capacity);
	}
	return vec->a;
}

R_API void *r_vector_shrink(RVector *vec) {
	if (vec->len < vec->capacity) {
		RESIZE_OR_RETURN_NULL (vec->len);
	}
	return vec->a;
}





static void pvector_free_elem(void *e, void *user) {
	void *p = *((void **)e);
	RPVectorFree elem_free = (RPVectorFree)user;
	elem_free (p);
}


R_API void r_pvector_init(RPVector *vec, RPVectorFree free) {
	r_vector_init (&vec->v, sizeof (void *), free ? pvector_free_elem : NULL, free);
}

R_API RPVector *r_pvector_new(RPVectorFree free) {
	RPVector *v = R_NEW (RPVector);
	if (!v) {
		return NULL;
	}
	r_pvector_init (v, free);
	return v;
}

R_API void r_pvector_clear(RPVector *vec) {
	r_vector_clear (&vec->v);
}

R_API void r_pvector_free(RPVector *vec) {
	if (!vec) {
		return;
	}
	r_vector_clear (&vec->v);
	free (vec);
}

R_API void **r_pvector_contains(RPVector *vec, void *x) {
	size_t i;
	for (i = 0; i < vec->v.len; i++) {
		if (((void **)vec->v.a)[i] == x) {
			return &((void **)vec->v.a)[i];
		}
	}
	return NULL;
}

R_API void *r_pvector_remove_at(RPVector *vec, size_t index) {
	void *r = r_pvector_at (vec, index);
	r_vector_remove_at (&vec->v, index, NULL);
	return r;
}

R_API void r_pvector_remove_data(RPVector *vec, void *x) {
	void **el = r_pvector_contains (vec, x);
	if (!el) {
		return;
	}

	size_t index = el - (void **)vec->v.a;
	r_vector_remove_at (&vec->v, index, NULL);
}

R_API void *r_pvector_pop(RPVector *vec) {
	void *r = r_pvector_at (vec, vec->v.len - 1);
	r_vector_pop (&vec->v, NULL);
	return r;
}

R_API void *r_pvector_pop_front(RPVector *vec) {
	void *r = r_pvector_at (vec, 0);
	r_vector_pop_front (&vec->v, NULL);
	return r;
}

// CLRS Quicksort. It is slow, but simple.
static void quick_sort(void **a, size_t n, RPVectorComparator cmp) {
	if (n <= 1) {
		return;
	}
	int i = rand() % n, j = 0;
	void *t, *pivot = a[i];
	a[i] = a[n - 1];
	for (i = 0; i < n - 1; i++) {
		if (cmp (a[i], pivot) < 0) {
			t = a[i];
			a[i] = a[j];
			a[j] = t;
			j++;
		}
	}
	a[n - 1] = a[j];
	a[j] = pivot;
	quick_sort (a, j, cmp);
	quick_sort (a + j + 1, n - j - 1, cmp);
}

R_API void r_pvector_sort(RPVector *vec, RPVectorComparator cmp) {
	quick_sort (vec->v.a, vec->v.len, cmp);
}
