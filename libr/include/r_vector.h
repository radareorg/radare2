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
  if (!r_vector_append (v, a)) goto err_append;
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
  r_vector_append (&v, (void *)1);
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

R_API void **r_vector_append(RVector *vec, void *x);
R_API void r_vector_clear(RVector *vec, void (*elem_free)(void *));
R_API RVector *r_vector_clone(RVector *vec);
R_API void **r_vector_contains(RVector *vec, void *x);
R_API void *r_vector_del_n(RVector *vec, int n);
R_API bool r_vector_empty(RVector *vec);
R_API void r_vector_fini(RVector *vec);
R_API void r_vector_free(RVector *vec, void (*elem_free)(void *));
R_API void r_vector_init(RVector *vec);
R_API void **r_vector_insert(RVector *vec, int n, void *x);
R_API RVector *r_vector_new(void);
R_API RVector *r_vector_new_replicate(int len, void *x);
R_API void *r_vector_pop(RVector *vec);
R_API void *r_vector_pop_first(RVector *vec);
R_API void **r_vector_prepend(RVector *vec, void *x);
R_API void **r_vector_reserve(RVector *vec, int capacity);
R_API void r_vector_sort(RVector *vec, RVectorComparator cmp);
/* shrink capacity to len, NB. delete operations do not shrink space */
R_API void **r_vector_shrink(RVector *vec);

#define r_vector_foreach(vec, it) \
	for (it = (vec)->a; it != (vec)->a + (vec)->len; it++)

#define r_vector_lower_bound(vec, x, i, cmp_less) \
  do { \
    int h = (vec)->len, m; \
    for (i = 0; i < h; ) { \
      m = i + ((h - i) >> 1); \
      if (cmp_less ((vec)->a[m], x)) { \
        i = m + 1; \
      } else { \
        h = m; \
      } \
    } \
  } while (0) \

#define r_vector_upper_bound(vec, x, i, cmp_less) \
  do { \
    int h = (vec)->len, m; \
    for (i = 0; i < h; ) { \
      m = i + ((h - i) >> 1); \
      if (!(cmp_less (x, (vec)->a[m]))) { \
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
