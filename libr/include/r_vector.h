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

typedef int (*RPVectorComparator)(const void *a, const void *b);
typedef void (*RVectorFree)(void *e, void *user);
typedef void (*RPVectorFree)(void *e);

typedef struct r_vector_t {
	void *a;
	size_t len;
	size_t capacity;
	size_t elem_size;
} RVector;

typedef struct r_pvector_t {
	RVector v;
	RPVectorFree free;
} RPVector;


// RVector

R_API void r_vector_init(RVector *vec, size_t elem_size);
R_API RVector *r_vector_new(size_t elem_size);
R_API void r_vector_free(RVector *vec, RVectorFree elem_free, void *user);
R_API void r_vector_clear(RVector *vec, RVectorFree elem_free, void *user);
R_API RVector *r_vector_clone(RVector *vec);

void *r_vector_index_ptr(RVector *vec, size_t index);
void r_vector_assign(RVector *vec, void *p, void *elem);
void *r_vector_assign_at(RVector *vec, size_t index, void *elem);

static inline bool r_vector_empty(RVector *vec)							{ return vec->len == 0; }
R_API void r_vector_remove_at(RVector *vec, size_t index, void *into);
R_API void *r_vector_insert(RVector *vec, size_t index, void *x);
R_API void *r_vector_insert_range(RVector *vec, size_t index, void *first, size_t count);
R_API void r_vector_pop(RVector *vec, void *into);
R_API void r_vector_pop_front(RVector *vec, void *into);
R_API void *r_vector_push(RVector *vec, void *x);
R_API void *r_vector_push_front(RVector *vec, void *x);
R_API void *r_vector_reserve(RVector *vec, size_t capacity);
/* shrink capacity to len, NB. delete operations do not shrink space */
R_API void *r_vector_shrink(RVector *vec);


// RPVector

R_API void r_pvector_init(RPVector *vec, RPVectorFree free);
R_API RPVector *r_pvector_new(RPVectorFree free);
R_API void r_pvector_clear(RPVector *vec);
R_API void r_pvector_free(RPVector *vec);
R_API RPVector *r_pvector_clone(RPVector *vec);

static inline size_t r_pvector_len(const RPVector *vec)					{ return vec->v.len; }
static inline void *r_pvector_at(const RPVector *vec, size_t index)		{ return ((void **)vec->v.a)[index]; }
static inline void r_pvector_set(RPVector *vec, size_t index, void *e)	{ ((void **)vec->v.a)[index] = e; }
static inline bool r_pvector_empty(RPVector *vec)						{ return r_pvector_len (vec) == 0; }

R_API void **r_pvector_contains(RPVector *vec, void *x);
R_API void *r_pvector_remove_at(RPVector *vec, size_t index);
static inline void **r_pvector_insert(RPVector *vec, size_t index, void *x) { return (void **)r_vector_insert (&vec->v, index, &x); }
static inline void **r_pvector_insert_range(RPVector *vec, size_t index, void **first, size_t count) { return r_vector_insert_range (&vec->v, index, first, count); }
R_API void *r_pvector_pop(RPVector *vec);
R_API void *r_pvector_pop_front(RPVector *vec);
static inline void **r_pvector_push(RPVector *vec, void *x) { return (void **)r_vector_push (&vec->v, &x); }
static inline void **r_pvector_push_front(RPVector *vec, void *x) { return (void **)r_vector_push_front (&vec->v, &x); }
R_API void r_pvector_sort(RPVector *vec, RPVectorComparator cmp);

static inline void **r_pvector_reserve(RPVector *vec, size_t capacity)	{ return (void **)r_vector_reserve (&vec->v, capacity); }
static inline void **r_pvector_shrink(RPVector *vec)					{ return (void **)r_vector_shrink (&vec->v); }

#define r_pvector_find(vec, it, cmp_eq) \
	for (it = (void **)(vec).v->a; it != (void **)(vec).v->a + (vec)->len && !(cmp_eq (*it, x)); it++);

#define r_pvector_foreach(vec, it) \
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)

#define r_pvector_lower_bound(vec, x, i, cmp) \
	do { \
		int h = (vec)->v.len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((void **)(vec)->v.a)[m])) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define r_pvector_upper_bound(vec, x, i, cmp) \
	do { \
		int h = (vec)->v.len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if (!((cmp (x, ((void **)(vec)->v.a)[m])) < 0)) { \
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
