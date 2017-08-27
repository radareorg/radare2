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
		int new_capacity = next_capacity; \
		void **new_a = realloc (vec->a, sizeof(void *) * new_capacity); \
		if (!new_a) { \
			return NULL; \
		} \
		vec->a = new_a; \
		vec->capacity = new_capacity; \
	} while (0)

R_API void r_vector_clear(RVector *vec, void (*elem_free)(void *)) {
	if (elem_free) {
		while (vec->len > 0) {
			elem_free (vec->a[--vec->len]);
		}
	} else {
		vec->len = 0;
	}
	R_FREE (vec->a);
	vec->capacity = 0;
}

R_API RVector *r_vector_clone(RVector *vec) {
	RVector *ret = R_NEW (RVector);
	if (ret) {
		ret->capacity = vec->capacity;
		ret->len = vec->len;
		if (!vec->len) {
			ret->a = NULL;
		} else {
			ret->a = malloc (sizeof (void *) * vec->len);
			if (!ret->a) {
				R_FREE (ret);
			} else {
				memcpy (ret->a, vec->a, sizeof (void *) * vec->len);
			}
		}
	}
	return ret;
}

R_API void **r_vector_contains(RVector *vec, void *x) {
	int i;
	for (i = 0; i < vec->len; i++) {
		if (vec->a[i] == x) {
			return &vec->a[i];
		}
	}
	return NULL;
}

R_API void *r_vector_delete_at(RVector *vec, int n) {
	void *ret = vec->a[n];
	vec->len--;
	for (; n < vec->len; n++) {
		vec->a[n] = vec->a[n+1];
	}
	return ret;
}

R_API bool r_vector_empty(RVector *vec) {
	return vec->len == 0;
}

R_API void r_vector_free(RVector *vec, void (*elem_free)(void *)) {
	if (elem_free) {
		while (vec->len > 0) {
			elem_free (vec->a[--vec->len]);
		}
	} else {
		vec->len = 0;
	}
	free (vec->a);
	free (vec);
}

R_API void r_vector_init(RVector *vec) {
	vec->a = NULL;
	vec->capacity = vec->len = 0;
}

R_API void **r_vector_insert(RVector *vec, int n, void *x) {
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL (NEXT_VECTOR_CAPACITY);
	}
	int i;
	for (i = vec->len++; i > n; i--) {
		vec->a[i] = vec->a[i-1];
	}
	vec->a[n] = x;
	return &vec->a[n];
}

R_API void **r_vector_insert_range(RVector *vec, int n, void **first, void **last) {
	if (last - first + vec->len > vec->capacity) {
		RESIZE_OR_RETURN_NULL (R_MAX (NEXT_VECTOR_CAPACITY, last - first + vec->len));
	}
	int i;
	for (i = vec->len; i > n; ) {
		i--;
		vec->a[last - first + i] = vec->a[i];
	}
	vec->len += last - first;
	i = n;
	while (first != last) {
		vec->a[i++] = *first++;
	}
	return &vec->a[n];
}

R_API RVector *r_vector_new(void) {
	return R_NEW0 (RVector);
}

R_API void *r_vector_pop(RVector *vec) {
	return vec->a[--vec->len];
}

R_API void *r_vector_pop_front(RVector *vec) {
	return r_vector_delete_at (vec, 0);
}

R_API void **r_vector_push(RVector *vec, void *x) {
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL (NEXT_VECTOR_CAPACITY);
	}
	vec->a[vec->len] = x;
	return &vec->a[vec->len++];
}

R_API void **r_vector_push_front(RVector *vec, void *x) {
	return r_vector_insert (vec, 0, x);
}

R_API void **r_vector_reserve(RVector *vec, int capacity) {
	if (vec->capacity < capacity) {
		RESIZE_OR_RETURN_NULL (capacity);
	}
	return vec->a;
}

R_API void **r_vector_shrink(RVector *vec) {
	if (vec->len < vec->capacity) {
		RESIZE_OR_RETURN_NULL (vec->len);
	}
	return vec->a;
}

// CLRS Quicksort. It is slow, but simple.
static void quick_sort(void **a, int n, RVectorComparator cmp) {
	if (n <= 1) return;
	int i = rand() % n, j = 0;
	void *t, *pivot = a[i];
	a[i] = a[n - 1];
	for (i = 0; i < n - 1; i++)
		if (cmp (a[i], pivot) < 0) {
			t = a[i];
			a[i] = a[j];
			a[j] = t;
			j++;
		}
	a[n - 1] = a[j];
	a[j] = pivot;
	quick_sort (a, j, cmp);
	quick_sort (a + j + 1, n - j - 1, cmp);
}

R_API void r_vector_sort(RVector *vec, RVectorComparator cmp) {
	quick_sort (vec->a, vec->len, cmp);
}

#if TEST
#include <assert.h>
#include <stddef.h>

int my_cmp(const void *a, const void *b) {
	return strcmp (a, b) < 0;
}

// TODO: move into t/vector.c
int main () {
	ptrdiff_t i;
	void **it;
	RVector *v = r_vector_new ();
	assert (*r_vector_push (v, (void *)1337) == (void *)1337);
	for (i = 0; i < 10; i++) {
		r_vector_push (v, (void *)i);
		assert (v->len == i + 2);
	}
	assert (r_vector_pop_front (v) == (void *)1337);
	assert (r_vector_contains (v, (void *)9));

	assert (r_vector_delete_at (v, 9) == (void *)9);
	assert (!r_vector_contains (v, (void *)9));

	i = 0;
	r_vector_foreach (v, it) {
		assert (*it == (void *)i++);
	}

	r_vector_shrink (v);
	assert (v->len == 9);
	RVector *v1 = r_vector_clone (v);
	r_vector_clear (v, NULL);
	assert (v->capacity == 0 && v->len == 0);
	assert (v1->len == 9);

	r_vector_free (v, NULL);
	r_vector_free (v1, NULL);

	RVector s;
	r_vector_init (&s);
	r_vector_reserve (&s, 10);
	r_vector_clear (&s, NULL);

	r_vector_reserve (&s, 10);
	r_vector_push (&s, (void *)-1);
	assert (s.len == 1 && s.capacity == 10);
	for (i = 0; i < 20; i++) {
		r_vector_push (&s, (void *)i);
	}
	r_vector_reserve (&s, 10);
	r_vector_clear (&s, NULL);

	{
		void *a[] = {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
		RVector s = {0};
		int l;
		r_vector_insert_range (&s, 0, a + 2, a + 5);
		r_vector_insert_range (&s, 0, a, a + 2);

#define CMP(x, y) x < y
		r_vector_lower_bound (&s, (void *)4, l, CMP);
		assert (s.a[l] == (void *)4);
		r_vector_lower_bound (&s, (void *)5, l, CMP);
		assert (s.a[l] == (void *)6);
		r_vector_lower_bound (&s, (void *)6, l, CMP);
		assert (s.a[l] == (void *)6);
		r_vector_lower_bound (&s, (void *)9, l, CMP);
		assert (l == s.len);

		r_vector_upper_bound (&s, (void *)4, l, CMP);
		assert (s.a[l] == (void *)6);
		r_vector_upper_bound (&s, (void *)5, l, CMP);
		assert (s.a[l] == (void *)6);
		r_vector_upper_bound (&s, (void *)6, l, CMP);
		assert (s.a[l] == (void *)8);
#undef CMP

		r_vector_clear (&s, NULL);

		r_vector_push (&s, strdup ("Charmander"));
		r_vector_push (&s, strdup ("Squirtle"));
		r_vector_push (&s, strdup ("Bulbasaur"));
		r_vector_push (&s, strdup ("Meowth"));
		r_vector_push (&s, strdup ("Caterpie"));
		r_vector_sort (&s, my_cmp);

		r_vector_lower_bound (&s, "Meow", l, strcmp);
		assert (!strcmp (s.a[l], "Meowth"));

		r_vector_clear (&s, free);
	}

	return 0;
}
#endif
