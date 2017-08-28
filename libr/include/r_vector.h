#ifndef R2_VECTOR_H
#define R2_VECTOR_H

#include <r_types.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
  Insert functions returns NULL if reallocation happens and fails,
  returns the address of newly inserted element if succeeded.

  Delete functions returns the deleted element.
  Callers should destruct it if necessary.

  Usage:
  int i;
  void **it;

  // heap allocated RVector
  RVector *v = r_vector_new ();
  if (!v) goto err_new;
  if (!r_vector_push (v, a)) goto err_push;
  if (!r_vector_insert (v, 0, b)) goto err_insert;
  for (i = 0; i < v->len; i++) {
    (void)v->a[i]; // Public members a and len are encouraged to access
  }
  r_vector_foreach (v, it) {
    (void)*it;
  }
  // pass function pointer `elem_free`
  r_vector_free (v, NULL);

  // stack allocated RVector
  RVector v = {0};
  // r_vector_init (&v); // v.a = NULL; v.len = v.capacity = 0;
  r_vector_push (&v, (void *)1);
  assert (v.len == 1 && v.capacity == 10);
  // for stack allocated RVector, use r_vector_clear instead of r_vector_free
  r_vector_clear (&v, NULL);
 */

typedef struct r_vector_t {
	void **a;
	int len;
	int capacity;
} RVector;

typedef int (*RVectorComparator)(const void *a, const void *b);

R_API void r_vector_clear(RVector *vec, void (*elem_free)(void *));
R_API RVector *r_vector_clone(RVector *vec);
R_API void **r_vector_contains(RVector *vec, void *x);
R_API void *r_vector_delete_at(RVector *vec, int n);
R_API bool r_vector_empty(RVector *vec);
R_API void r_vector_fini(RVector *vec);
R_API void r_vector_free(RVector *vec, void (*elem_free)(void *));
R_API void r_vector_init(RVector *vec);
R_API void **r_vector_insert(RVector *vec, int n, void *x);
R_API void **r_vector_insert_range(RVector *vec, int n, void **first, void **last);
R_API RVector *r_vector_new(void);
R_API void *r_vector_pop(RVector *vec);
R_API void *r_vector_pop_front(RVector *vec);
R_API void **r_vector_push(RVector *vec, void *x);
R_API void **r_vector_push_front(RVector *vec, void *x);
R_API void **r_vector_reserve(RVector *vec, int capacity);
/* shrink capacity to len, NB. delete operations do not shrink space */
R_API void **r_vector_shrink(RVector *vec);
R_API void r_vector_sort(RVector *vec, RVectorComparator cmp);

#define r_vector_find(vec, it, cmp_eq) \
	for (it = (vec)->a; it != (vec)->a + (vec)->len && !(cmp_eq (*it, x)); it++);

#define r_vector_foreach(vec, it) \
	for (it = (vec)->a; it != (vec)->a + (vec)->len; it++)

#define r_vector_lower_bound(vec, x, i, cmp) \
	do { \
		int h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if (cmp ((vec)->a[m], x) < 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define r_vector_upper_bound(vec, x, i, cmp) \
	do { \
		int h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if (!(cmp (x, (vec)->a[m]) < 0)) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#ifdef __cplusplus
}
#endif

#endif
