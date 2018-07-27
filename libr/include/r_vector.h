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
	void *a;
	size_t len;
	size_t capacity;
	size_t elem_size;
} RVector;

typedef int (*RPVectorComparator)(const void *a, const void *b);
typedef void (*RVectorFree)(void *e, void *user);
typedef void (*RPVectorFree)(void *e);

R_API void r_vector_init(RVector *vec, size_t elem_size);
R_API RVector *r_vector_new(size_t elem_size);
R_API void r_vector_free(RVector *vec, RVectorFree elem_free, void *user);
R_API void r_vector_clear(RVector *vec, RVectorFree elem_free, void *user);
R_API RVector *r_vector_clone(RVector *vec);

R_API bool r_vector_empty(RVector *vec);
R_API void r_vector_delete_at(RVector *vec, size_t index, void *into);
R_API void *r_vector_insert(RVector *vec, size_t index, void *x);
R_API void *r_vector_insert_range(RVector *vec, size_t index, void *first, size_t count);
R_API void r_vector_pop(RVector *vec, void *into);
R_API void r_vector_pop_front(RVector *vec, void *into);
R_API void *r_vector_push(RVector *vec, void *x);
R_API void *r_vector_push_front(RVector *vec, void *x);
R_API void *r_vector_reserve(RVector *vec, size_t capacity);
/* shrink capacity to len, NB. delete operations do not shrink space */
R_API void *r_vector_shrink(RVector *vec);

static inline void r_pvector_init(RVector *vec)	{ r_vector_init (vec, sizeof (void *)); }
static inline RVector *r_pvector_new()			{ return r_vector_new (sizeof (void *)); }
R_API void r_pvector_free(RVector *vec, RPVectorFree elem_free);
R_API void r_pvector_clear(RVector *vec, RPVectorFree);

static inline void *r_pvector_at(const RVector *vec, size_t index)		{ return ((void **)vec->a)[index]; }
static inline void r_pvector_set(RVector *vec, size_t index, void *e)	{ ((void **)vec->a)[index] = e; }

R_API void **r_pvector_contains(RVector *vec, void *x);
R_API void *r_pvector_delete_at(RVector *vec, size_t index);
static inline void **r_pvector_insert(RVector *vec, size_t index, void *x) { return (void **)r_vector_insert (vec, index, &x); }
R_API void *r_pvector_pop(RVector *vec);
R_API void *r_pvector_pop_front(RVector *vec);
static inline void **r_pvector_push(RVector *vec, void *x) { return (void **)r_vector_push (vec, &x); }
static inline void **r_pvector_push_front(RVector *vec, void *x) { return (void **)r_vector_push_front (vec, &x); }
R_API void r_pvector_sort(RVector *vec, RPVectorComparator cmp);

#define r_pvector_find(vec, it, cmp_eq) \
	for (it = (void **)(vec)->a; it != (void **)(vec)->a + (vec)->len && !(cmp_eq (*it, x)); it++);

#define r_pvector_foreach(vec, it) \
	for (it = (void **)(vec)->a; it != (void **)(vec)->a + (vec)->len; it++)

#define r_pvector_lower_bound(vec, x, i, cmp) \
	do { \
		int h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((void **)(vec)->a)[m])) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define rp_vector_upper_bound(vec, x, i, cmp) \
	do { \
		int h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if (!((cmp (x, ((void **)(vec)->a)[m])) < 0)) { \
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
