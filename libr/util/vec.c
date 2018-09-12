#include "r_vec.h"

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
		
		

R_API void r_vec_init(RVec *vec, size_t elem_size, RVecFree free, void *free_user) {
	vec->a = NULL;
	vec->capacity = vec->len = 0;
	vec->elem_size = elem_size;
	vec->free = free;
	vec->free_user = free_user;
}

R_API RVec *r_vec_new(size_t elem_size, RVecFree free, void *free_user) {
	RVec *vec = R_NEW (RVec);
	if (!vec) {
		return NULL;
	}
	r_vec_init (vec, elem_size, free, free_user);
	return vec;
}

static void vector_free_elems(RVec *vec) {
	if (vec->free) {
		while (vec->len > 0) {
			vec->free (r_vec_index_ptr (vec, --vec->len), vec->free_user);
		}
	} else {
		vec->len = 0;
	}
}

R_API void r_vec_clear(RVec *vec) {
	vector_free_elems (vec);
	R_FREE (vec->a);
	vec->capacity = 0;
}

R_API void r_vec_free(RVec *vec) {
	vector_free_elems (vec);
	free (vec->a);
	free (vec);
}

static bool vector_clone(RVec *dst, RVec *src) {
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

R_API RVec *r_vec_clone(RVec *vec) {
	RVec *ret = R_NEW (RVec);
	if (!ret) {
		return NULL;
	}
	if (!vector_clone (ret, vec)) {
		free (ret);
		return NULL;
	}
	return ret;
}



R_API void *r_vec_index_ptr(RVec *vec, size_t index) {
	return (char *)vec->a + vec->elem_size * index;
}

R_API void r_vec_assign(RVec *vec, void *p, void *elem) {
	memcpy (p, elem, vec->elem_size);
}

R_API void *r_vec_assign_at(RVec *vec, size_t index, void *elem) {
	void *p = r_vec_index_ptr (vec, index);
	r_vec_assign (vec, p, elem);
	return p;
}

R_API void r_vec_remove_at(RVec *vec, size_t index, void *into) {
	void *p = r_vec_index_ptr (vec, index);
	if (into) {
		r_vec_assign (vec, into, p);
	}
	vec->len--;
	if (index < vec->len) {
		memmove (p, (char *)p + vec->elem_size, vec->elem_size * (vec->len - index));
	}
}



R_API void *r_vec_insert(RVec *vec, size_t index, void *x) {
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL (NEXT_VECTOR_CAPACITY);
	}
	void *p = r_vec_index_ptr (vec, index);
	if (index < vec->len) {
		memmove ((char *)p + vec->elem_size, p, vec->elem_size * (vec->len - index));
	}
	vec->len++;
	if (x) {
		r_vec_assign (vec, p, x);
	}
	return p;
}

R_API void *r_vec_insert_range(RVec *vec, size_t index, void *first, size_t count) {
	if (vec->len + count > vec->capacity) {
		RESIZE_OR_RETURN_NULL (R_MAX (NEXT_VECTOR_CAPACITY, vec->len + count));
	}
	size_t sz = count * vec->elem_size;
	void *p = r_vec_index_ptr (vec, index);
	if (index < vec->len) {
		memmove ((char *)p + sz, p, vec->elem_size * (vec->len - index));
	}
	vec->len += count;
	if (first) {
		memcpy (p, first, sz);
	}
	return p;
}

R_API void r_vec_pop(RVec *vec, void *into) {
	if (into) {
		r_vec_assign (vec, into, r_vec_index_ptr (vec, vec->len - 1));
	}
	vec->len--;
}

R_API void r_vec_pop_front(RVec *vec, void *into) {
	r_vec_remove_at (vec, 0, into);
}

R_API void *r_vec_push(RVec *vec, void *x) {
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL (NEXT_VECTOR_CAPACITY);
	}
	void *p = r_vec_index_ptr (vec, vec->len++);
	if (x) {
		r_vec_assign (vec, p, x);
	}
	return p;
}

R_API void *r_vec_push_front(RVec *vec, void *x) {
	return r_vec_insert (vec, 0, x);
}

R_API void *r_vec_reserve(RVec *vec, size_t capacity) {
	if (vec->capacity < capacity) {
		RESIZE_OR_RETURN_NULL (capacity);
	}
	return vec->a;
}

R_API void *r_vec_shrink(RVec *vec) {
	if (vec->len < vec->capacity) {
		RESIZE_OR_RETURN_NULL (vec->len);
	}
	return vec->a;
}





static void pvector_free_elem(void *e, void *user) {
	void *p = *((void **)e);
	RPVecFree elem_free = (RPVecFree)user;
	elem_free (p);
}


R_API void r_pvec_init(RPVec *vec, RPVecFree free) {
	r_vec_init (&vec->v, sizeof (void *), free ? pvector_free_elem : NULL, free);
}

R_API RPVec *r_pvec_new(RPVecFree free) {
	RPVec *v = R_NEW (RPVec);
	if (!v) {
		return NULL;
	}
	r_pvec_init (v, free);
	return v;
}

R_API void r_pvec_clear(RPVec *vec) {
	r_vec_clear (&vec->v);
}

R_API void r_pvec_free(RPVec *vec) {
	if (!vec) {
		return;
	}
	r_vec_clear (&vec->v);
	free (vec);
}

R_API void **r_pvec_contains(RPVec *vec, void *x) {
	size_t i;
	for (i = 0; i < vec->v.len; i++) {
		if (((void **)vec->v.a)[i] == x) {
			return &((void **)vec->v.a)[i];
		}
	}
	return NULL;
}

R_API void *r_pvec_remove_at(RPVec *vec, size_t index) {
	void *r = r_pvec_at (vec, index);
	r_vec_remove_at (&vec->v, index, NULL);
	return r;
}

R_API void *r_pvec_pop(RPVec *vec) {
	void *r = r_pvec_at (vec, vec->v.len - 1);
	r_vec_pop (&vec->v, NULL);
	return r;
}

R_API void *r_pvec_pop_front(RPVec *vec) {
	void *r = r_pvec_at (vec, 0);
	r_vec_pop_front (&vec->v, NULL);
	return r;
}

// CLRS Quicksort. It is slow, but simple.
static void quick_sort(void **a, size_t n, RPVecComparator cmp) {
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

R_API void r_pvec_sort(RPVec *vec, RPVecComparator cmp) {
	quick_sort (vec->v.a, vec->v.len, cmp);
}
