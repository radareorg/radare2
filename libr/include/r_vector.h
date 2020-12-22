#ifndef R2_VECTOR_H
#define R2_VECTOR_H

#include <r_types.h>
#include <r_util/r_assert.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * RVector can contain arbitrarily sized elements.
 * RPVector uses RVector internally and always contains void *s
 *
 * Thus, for storing pointers it is highly encouraged to always use RPVector
 * as it is specifically made for this purpose and is more consistent with RList,
 * while RVector can be used as, for example, a flat array of a struct.
 *
 * Notable differences between RVector and RPVector:
 * -------------------------------------------------
 * When RVector expects an element to be inserted, for example in r_vector_push(..., void *x),
 * this void * value is interpreted as a pointer to the actual data for the element.
 * => If you use RVector as a dynamic replacement for (struct SomeStruct)[], you will
 * pass a struct SomeStruct * to these functions.
 *
 * Because RPVector only handles pointers, the given void * is directly interpreted as the
 * actual pointer to be inserted.
 * => If you use RPVector as a dynamic replacement for (SomeType *)[], you will pass
 * SomeType * directly to these functions.
 *
 * The same differentiation goes for the free functions:
 * - The element parameter in RVectorFree is a pointer to the element inside the array.
 * - The element parameter in RPVectorFree is the actual pointer stored in the array.
 *
 * General Hint:
 * -------------
 * remove/pop functions do not reduce the capacity.
 * Call r_(p)vector_shrink explicitly if desired.
 */

typedef int (*RPVectorComparator)(const void *a, const void *b);
typedef void (*RVectorFree)(void *e, void *user);
typedef void (*RPVectorFree)(void *e);

typedef struct r_vector_t {
	void *a;
	size_t len;
	size_t capacity;
	size_t elem_size;
	RVectorFree free;
	void *free_user;
} RVector;

// RPVector directly wraps RVector for type safety
typedef struct r_pvector_t { RVector v; } RPVector;


// RVector

R_API void r_vector_init(RVector *vec, size_t elem_size, RVectorFree free, void *free_user);

R_API RVector *r_vector_new(size_t elem_size, RVectorFree free, void *free_user);

// clears the vector and calls vec->free on every element if set.
R_API void r_vector_fini(RVector *vec);

// frees the vector and calls vec->free on every element if set.
R_API void r_vector_free(RVector *vec);

// the returned vector will have the same capacity as vec.
R_API RVector *r_vector_clone(RVector *vec);

static inline bool r_vector_empty(const RVector *vec) {
	r_return_val_if_fail (vec, false);
	return vec->len == 0;
}

R_API void r_vector_clear(RVector *vec);

// returns the length of the vector
static inline size_t r_vector_len(const RVector *vec) {
	r_return_val_if_fail (vec, 0);
	return vec->len;
}

// returns a pointer to the offset inside the array where the element of the index lies.
static inline void *r_vector_index_ptr(RVector *vec, size_t index) {
	r_return_val_if_fail (vec && index < vec->capacity, NULL);
	return (char *)vec->a + vec->elem_size * index;
}

// helper function to assign an element of size vec->elem_size from elem to p.
// elem is a pointer to the actual data to assign!
R_API void r_vector_assign(RVector *vec, void *p, void *elem);

// assign the value of size vec->elem_size at elem to vec at the given index.
// elem is a pointer to the actual data to assign!
R_API void *r_vector_assign_at(RVector *vec, size_t index, void *elem);

// remove the element at the given index and write the content to into.
// It is the caller's responsibility to free potential resources associated with the element.
R_API void r_vector_remove_at(RVector *vec, size_t index, void *into);

// insert the value of size vec->elem_size at x at the given index.
// x is a pointer to the actual data to assign!
R_API void *r_vector_insert(RVector *vec, size_t index, void *x);

// insert count values of size vec->elem_size into vec starting at the given index.
R_API void *r_vector_insert_range(RVector *vec, size_t index, void *first, size_t count);

// like r_vector_remove_at for the last element
R_API void r_vector_pop(RVector *vec, void *into);

// like r_vector_remove_at for the first element
R_API void r_vector_pop_front(RVector *vec, void *into);

// like r_vector_insert for the end of vec
R_API void *r_vector_push(RVector *vec, void *x);

// like r_vector_insert for the beginning of vec
R_API void *r_vector_push_front(RVector *vec, void *x);

// make sure the capacity is at least capacity.
R_API void *r_vector_reserve(RVector *vec, size_t capacity);

// shrink capacity to len.
R_API void *r_vector_shrink(RVector *vec);

/*
 * example:
 *
 * RVector *v = ...; // <contains MyStruct>
 * MyStruct *it;
 * r_vector_foreach (v, it) {
 *     // Do something with it
 * }
 */
#define r_vector_foreach(vec, it) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))

#define r_vector_foreach_prev(vec, it) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)((char *)(vec)->a + (((vec)->len - 1)* (vec)->elem_size)); (char *)it != (char *)(vec)->a; it = (void *)((char *)it - (vec)->elem_size))

#define r_vector_enumerate(vec, it, i) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)(vec)->a, i = 0; i < (vec)->len; it = (void *)((char *)it + (vec)->elem_size), i++)

/*
 * example:
 *
 * RVector *v = ...; // contains {(st64)0, (st64)2, (st64)4, (st64)6, (st64)8};
 * size_t l;
 * #define CMP(x, y) x - (*(st64 *)y)
 * r_vector_lower_bound (v, 3, l, CMP);
 * // l == 2
 */
#define r_vector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((char *)(vec)->a + (vec)->elem_size * m))) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define r_vector_upper_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((char *)(vec)->a + (vec)->elem_size * m))) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0) \

// RPVector

R_API void r_pvector_init(RPVector *vec, RPVectorFree free);
R_API void r_pvector_fini(RPVector *vec);

R_API RPVector *r_pvector_new(RPVectorFree free);

R_API RPVector *r_pvector_new_with_len(RPVectorFree free, size_t length);

// clear the vector and call vec->v.free on every element.
R_API void r_pvector_clear(RPVector *vec);

// free the vector and call vec->v.free on every element.
R_API void r_pvector_free(RPVector *vec);

static inline size_t r_pvector_len(const RPVector *vec) {
	r_return_val_if_fail (vec, 0);
	return vec->v.len;
}

static inline void *r_pvector_at(const RPVector *vec, size_t index) {
	r_return_val_if_fail (vec && index < vec->v.len, NULL);
	return ((void **)vec->v.a)[index];
}

static inline void r_pvector_set(RPVector *vec, size_t index, void *e) {
	r_return_if_fail (vec && index < vec->v.len);
	((void **)vec->v.a)[index] = e;
}

static inline bool r_pvector_empty(RPVector *vec) {
	return r_pvector_len (vec) == 0;
}

// returns a pointer to the offset inside the array where the element of the index lies.
static inline void **r_pvector_index_ptr(RPVector *vec, size_t index) {
	r_return_val_if_fail (vec && index < vec->v.capacity, NULL);
	return ((void **)vec->v.a) + index;
}

// same as r_pvector_index_ptr(<vec>, 0)
static inline void **r_pvector_data(RPVector *vec) {
	r_return_val_if_fail (vec, NULL);
	return (void **)vec->v.a;
}

// returns the respective pointer inside the vector if x is found or NULL otherwise.
R_API void **r_pvector_contains(RPVector *vec, void *x);

// removes and returns the pointer at the given index. Does not call free.
R_API void *r_pvector_remove_at(RPVector *vec, size_t index);

// removes the element x, if present. Does not call free.
R_API void r_pvector_remove_data(RPVector *vec, void *x);

// like r_vector_insert, but the pointer x is the actual data to be inserted.
static inline void **r_pvector_insert(RPVector *vec, size_t index, void *x) {
	return (void **)r_vector_insert (&vec->v, index, &x);
}

// like r_vector_insert_range.
static inline void **r_pvector_insert_range(RPVector *vec, size_t index, void **first, size_t count) {
	return (void **)r_vector_insert_range (&vec->v, index, first, count);
}

// like r_vector_pop, but returns the pointer directly.
R_API void *r_pvector_pop(RPVector *vec);

// like r_vector_pop_front, but returns the pointer directly.
R_API void *r_pvector_pop_front(RPVector *vec);

// like r_vector_push, but the pointer x is the actual data to be inserted.
static inline void **r_pvector_push(RPVector *vec, void *x) {
	return (void **)r_vector_push (&vec->v, &x);
}

// like r_vector_push_front, but the pointer x is the actual data to be inserted.
static inline void **r_pvector_push_front(RPVector *vec, void *x) {
	return (void **)r_vector_push_front (&vec->v, &x);
}

// sort vec using quick sort.
R_API void r_pvector_sort(RPVector *vec, RPVectorComparator cmp);

static inline void **r_pvector_reserve(RPVector *vec, size_t capacity) {
	return (void **)r_vector_reserve (&vec->v, capacity);
}

static inline void **r_pvector_shrink(RPVector *vec) {
	return (void **)r_vector_shrink (&vec->v);
}

/*
 * example:
 *
 * RVector *v = ...;
 * void **it;
 * r_pvector_foreach (v, it) {
 *     void *p = *it;
 *     // Do something with p
 * }
 */
#define r_pvector_foreach(vec, it) \
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)

// like r_pvector_foreach() but inverse
#define r_pvector_foreach_prev(vec, it) \
	for (it = ((vec)->v.len == 0 ? NULL : (void **)(vec)->v.a + (vec)->v.len - 1); it != NULL && it != (void **)(vec)->v.a - 1; it--)

/*
 * example:
 *
 * RPVector *v = ...; // contains {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
 * size_t index;
 * #define CMP(x, y) x - y
 * r_pvector_lower_bound (v, (void *)3, index, CMP);
 * // index == 2
 */
#define r_pvector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->v.len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp ((x), ((void **)(vec)->v.a)[m])) > 0) { \
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
