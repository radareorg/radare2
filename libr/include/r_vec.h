#ifndef R2_VECTOR_H
#define R2_VECTOR_H

#include <r_types.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * RVec can contain arbitrarily sized elements.
 * RPVec uses RVec internally and always contains void *s
 *
 * Thus, for storing pointers it is highly encouraged to always use RPVec
 * as it is specifically made for this purpose and is more consistent with RList,
 * while RVec can be used as, for example, a flat array of a struct.
 *
 * Notable differences between RVec and RPVec:
 * -------------------------------------------------
 * When RVec expects an element to be inserted, for example in r_vec_push(..., void *x),
 * this void * value is interpreted as a pointer to the actual data for the element.
 * => If you use RVec as a dynamic replacement for (struct SomeStruct)[], you will
 * pass a struct SomeStruct * to these functions.
 *
 * Because RPVec only handles pointers, the given void * is directly interpreted as the
 * actual pointer to be inserted.
 * => If you use RPVec as a dynamic replacement for (SomeType *)[], you will pass
 * SomeType * directly to these functions.
 *
 * The same differentiation goes for the free functions:
 * - The element parameter in RVecFree is a pointer to the element inside the array.
 * - The element parameter in RPVecFree is the actual pointer stored in the array.
 *
 * General Hint:
 * -------------
 * remove/pop functions do not reduce the capacity.
 * Call r_(p)vector_shrink explicitly if desired.
 */

typedef int (*RPVecComparator)(const void *a, const void *b);
typedef void (*RVecFree)(void *e, void *user);
typedef void (*RPVecFree)(void *e);

typedef struct r_vec_t {
	void *a;
	size_t len;
	size_t capacity;
	size_t elem_size;
	RVecFree free;
	void *free_user;
} RVec;

// RPVec directly wraps RVec for type safety
typedef struct r_pvec_t { RVec v; } RPVec;


// RVec

R_API void r_vec_init(RVec *vec, size_t elem_size, RVecFree free, void *free_user);

R_API RVec *r_vec_new(size_t elem_size, RVecFree free, void *free_user);

// clears the vector and calls vec->free on every element if set.
R_API void r_vec_clear(RVec *vec);

// frees the vector and calls vec->free on every element if set.
R_API void r_vec_free(RVec *vec);

// the returned vector will have the same capacity as vec.
R_API RVec *r_vec_clone(RVec *vec);

static inline bool r_vec_empty(RVec *vec) {
	return vec->len == 0;
}

// returns a pointer to the offset inside the array where the element of the index lies.
R_API void *r_vec_index_ptr(RVec *vec, size_t index);

// helper function to assign an element of size vec->elem_size from elem to p.
// elem is a pointer to the actual data to assign!
R_API void r_vec_assign(RVec *vec, void *p, void *elem);

// assign the value of size vec->elem_size at elem to vec at the given index.
// elem is a pointer to the actual data to assign!
R_API void *r_vec_assign_at(RVec *vec, size_t index, void *elem);

// remove the element at the given index and write the content to into.
// It is the caller's responsibility to free potential resources associated with the element.
R_API void r_vec_remove_at(RVec *vec, size_t index, void *into);

// insert the value of size vec->elem_size at x at the given index.
// x is a pointer to the actual data to assign!
R_API void *r_vec_insert(RVec *vec, size_t index, void *x);

// insert count values of size vec->elem_size into vec starting at the given index.
R_API void *r_vec_insert_range(RVec *vec, size_t index, void *first, size_t count);

// like r_vec_remove_at for the last element
R_API void r_vec_pop(RVec *vec, void *into);

// like r_vec_remove_at for the first element
R_API void r_vec_pop_front(RVec *vec, void *into);

// like r_vec_insert for the end of vec
R_API void *r_vec_push(RVec *vec, void *x);

// like r_vec_insert for the beginning of vec
R_API void *r_vec_push_front(RVec *vec, void *x);

// make sure the capacity is at least capacity.
R_API void *r_vec_reserve(RVec *vec, size_t capacity);

// shrink capacity to len.
R_API void *r_vec_shrink(RVec *vec);

/*
 * example:
 *
 * RVec *v = ...; // <contains MyStruct>
 * MyStruct *it;
 * r_vec_foreach (v, it) {
 *     // Do something with it
 * }
 */
#define r_vec_foreach(vec, it) \
	if ((vec) && (vec)->a) \
		for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))


// RPVec

R_API void r_pvec_init(RPVec *vec, RPVecFree free);

R_API RPVec *r_pvec_new(RPVecFree free);

// clear the vector and call vec->v.free on every element.
R_API void r_pvec_clear(RPVec *vec);

// free the vector and call vec->v.free on every element.
R_API void r_pvec_free(RPVec *vec);

static inline size_t r_pvec_len(const RPVec *vec) {
	return vec->v.len;
}

static inline void *r_pvec_at(const RPVec *vec, size_t index) {
	return ((void **)vec->v.a)[index];
}

static inline void r_pvec_set(RPVec *vec, size_t index, void *e) {
	((void **)vec->v.a)[index] = e;
}

static inline bool r_pvec_empty(RPVec *vec) {
	return r_pvec_len (vec) == 0;
}

// returns the respective pointer inside the vector if x is found or NULL otherwise.
R_API void **r_pvec_contains(RPVec *vec, void *x);

// removes and returns the pointer at the given index. Does not call free.
R_API void *r_pvec_remove_at(RPVec *vec, size_t index);

// like r_vec_insert, but the pointer x is the actual data to be inserted.
static inline void **r_pvec_insert(RPVec *vec, size_t index, void *x) {
	return (void **)r_vec_insert (&vec->v, index, &x); }

// like r_vec_insert_range.
static inline void **r_pvec_insert_range(RPVec *vec, size_t index, void **first, size_t count) {
	return (void **)r_vec_insert_range (&vec->v, index, first, count);
}

// like r_vec_pop, but returns the pointer directly.
R_API void *r_pvec_pop(RPVec *vec);

// like r_vec_pop_front, but returns the pointer directly.
R_API void *r_pvec_pop_front(RPVec *vec);

// like r_vec_push, but the pointer x is the actual data to be inserted.
static inline void **r_pvec_push(RPVec *vec, void *x) {
	return (void **)r_vec_push (&vec->v, &x);
}

// like r_vec_push_front, but the pointer x is the actual data to be inserted.
static inline void **r_pvec_push_front(RPVec *vec, void *x) {
	return (void **)r_vec_push_front (&vec->v, &x);
}

// sort vec using quick sort.
R_API void r_pvec_sort(RPVec *vec, RPVecComparator cmp);

static inline void **r_pvec_reserve(RPVec *vec, size_t capacity) {
	return (void **)r_vec_reserve (&vec->v, capacity);
}

static inline void **r_pvec_shrink(RPVec *vec) {
	return (void **)r_vec_shrink (&vec->v);
}

/*
 * example:
 *
 * RVec *v = ...;
 * void **it;
 * r_pvec_foreach (v, it) {
 *     void *p = *it;
 *     // Do something with p
 * }
 */
#define r_pvec_foreach(vec, it) \
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)

/*
 * example:
 *
 * RPVec *v = ...; // contains {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
 * size_t l;
 * #define CMP(x, y) x - y
 * r_pvec_lower_bound (v, (void *)3, l, CMP);
 * // l == 2
 */
#define r_pvec_lower_bound(vec, x, i, cmp) \
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

// see r_pvec_lower_bound
#define r_pvec_upper_bound(vec, x, i, cmp) \
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
