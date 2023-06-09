#ifndef R2_VEC_H
#define R2_VEC_H

#include <r_util/r_assert.h>
#include <r_types.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A new vector (resizable array) implementation, similar to std::vector in
 * C++ and std::vec::Vec in Rust. Unlike in those languages, C does not have
 * templates and instead relies on macros to generate 1 concrete implementation per type.
 *
 * Note that compared to the older r_vector and r_pvector types in R2, there is
 * only a single type that exists for both usecases.
 *
 * The way to use this code is as follows:
 * 1. Use the R_GENERATE_VEC_IMPL_FOR macro to generate the vector implementation for a certain type
 * 2. Use the R_VEC macro to refer to vector types.
 * 3. Call the functions from the API (described below), e.g. MyVector_init (&vec).
 *    Note that these are auto-generated with the macro in step 1.
 * 4. Do not access the fields in the vector struct directly, instead always use the functions from
 *    the API.
 *
 * Vector API:
 * - void R_VEC_FUNC(name, init)(R_VEC(name) *vec): Initializes an empty vector.
 * - R_VEC(name) *R_VEC_FUNC(name, new)(): Allocates a new empty vector on the heap.
 * - void R_VEC_FUNC(name, swap)(R_VEC(name) *vec_a, R_VEC(name) *vec_b): Swaps 2 vectors.
 * - void R_VEC_FUNC(name, clear)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user):
 *   Clears the vector by calling fini_fn for each element. The size is set to 0,
 *   but the capacity remains the same (no allocation is freed).
 * - void R_VEC_FUNC(name, fini)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user):
 *   Clears the vector by calling fini_fn for each element. Also frees up all memory used
 *   by the vector elements.
 * - void R_VEC_FUNC(name, free)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user):
 *   Similar to R_VEC_FUNC(name, fini), but also frees the vector itself.
 * - size_t R_VEC_FUNC(name, length)(const R_VEC(name) *vec): Returns number of elements
 *   in the vector.
 * - size_t R_VEC_FUNC(name, capacity)(const R_VEC(name) *vec): Returns the max number of
 *   elements that can fit in the vector before a re-allocation needs to be performed.
 * - bool R_VEC_FUNC(name, empty)(const R_VEC(name) *vec): Returns a boolean value indicating
 *   if the vector is empty or not.
 * - type *R_VEC_FUNC(name, start_iter)(const R_VEC(name) *vec): Returns a pointer to the start
 *   of the elements in the vector.
 * - type *R_VEC_FUNC(name, end_iter)(const R_VEC(name) *vec): Returns a pointer to element PAST
 *   the end of the last filled in element in the vector.
 * - type *R_VEC_FUNC(name, at)(const R_VEC(name) *vec, size_t index): Returns a pointer to an
 *   element in the vector. Note that this can be used for reading or writing from/to the element,
 *   but not deleting (see the pop and remove functions for this).
 * - R_VEC(name) *R_VEC_FUNC(name, clone)(const R_VEC(name) *vec): Creates a shallow clone of a vector.
 * - void R_VEC_FUNC(name, reserve)(R_VEC(name) *vec, size_t new_capacity): Ensures the vector has
 *   atleast a capacity of "new_capacity".
 * - void R_VEC_FUNC(name, shrink_to_fit)(R_VEC(name) *vec): Shrinks the vector to exactly fit the
 *   current number of elements it contains.
 * - void R_VEC_FUNC(name, push_back)(R_VEC(name) *vec, type *value): Appends a single element to
 *   the end of the vector.
 * - void R_VEC_FUNC(name, push_front)(R_VEC(name) *vec, type *value): Prepends a single element to
 *   the front of the vector. All following elements are shifted one place.
 * - void R_VEC_FUNC(name, append)(R_VEC(name) *vec, R_VEC(name) *values): Appends the elements of
 *   the second vector to the first. Note that only a shallow copy is made for each element, so do
 *   not pass in a fini_fn when you are freeing the second vector to avoid double frees!
 * - void R_VEC_FUNC(name, remove)(R_VEC(name) *vec, size_t index, R_VEC_FINI(name) fini_fn, void *user):
 *   Calls the fini_fn on the Nth element of the vector, and then removes it. All subsequent
 *   elements are shifted 1 toward the beginning of the vector.
 * - void R_VEC_FUNC(name, pop_front)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user):
 *   Calls the fini_fn on the first element of the vector, and then removes it. All subsequent
 *   elements are shifted 1 toward the beginning of the vector.
 * - void R_VEC_FUNC(name, pop_back)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user):
 *   Calls the fini_fn on the last element of the vector, and then removes it.
 * - size_t R_VEC_FUNC(name, lower_bound)(R_VEC(name) *vec, type *value, R_VEC_CMP(type) cmp_fn):
 *   Calculates the lower bound of a value in a vector. Returns the index to the element containing
 *   the lower bound.
 * - size_t R_VEC_FUNC(name, upper_bound)(R_VEC(name) *vec, type *value, R_VEC_CMP(type) cmp_fn):
 *   Calculates the upper bound of a value in a vector. Returns the index to the element containing
 *   the upper bound.
 */

// Helper macro for doing a foreach-style loop over the elements of a vector.
#define R_VEC_FOREACH(vec, iter) for (iter = (vec)->start; iter != (vec)->end; iter++)
#define R_VEC_FOREACH_PREV(vec, iter) \
	for (iter = (vec)->end - 1; iter >= (vec)->start; iter--)

#define R_CONCAT_INNER(a, b) a ## b
#define R_CONCAT(a, b) R_CONCAT_INNER(a, b)

// Helper macro for referring to a vector type that was previously generated. It is only used
// internally to simplify some of the macro code.
#define R_VEC(name) R_CONCAT(RVec, name)

// Helper macro for referring to finalizer functions of types stored in a "R_VEC(name)".
#define R_VEC_FINI(name) R_CONCAT(R_VEC(name), Fini)

// Helper macro for referring to comparison functions of types stored in a "R_VEC(type)".
#define R_VEC_CMP(name) R_CONCAT(RVecCompare, name)

// Helper macro for referring to functions of a "R_VEC(name)". It is only used internally
// to simplify some of the macro code.
#define R_VEC_FUNC(name, fn) R_CONCAT(R_CONCAT(R_VEC(name), _), fn)

// Helper macro for forward declaring a vector type. Useful for when you want
// to use a vector in a header file that is used in a lot of places without
// generating all the code for the implementation (at the cost of a pointer-indirection).
#define R_VEC_FORWARD_DECLARE(name) \
	R_CONCAT(R_CONCAT(R_CONCAT(typedef struct r_vec_, name), _t), R_VEC(name))

#define R_MAYBE_UNUSED __attribute__((unused))

// The main macro that generates the implementation for a vector.
// This should only be used once per type in a single compilation unit,
// otherwise you will end up with duplicate symbols.
//
// Because of the way headers work in C, you should try to avoid using this in
// header files, or the pre-processor will include the generated code in each
// of the files that includes this header file. If you want to avoid this,
// you can forward declare a vector type (at the cost of a pointer-indirection).
#define R_GENERATE_VEC_IMPL_FOR(name, type) \
	typedef struct r_vec_ ## name ## _t { \
		type *start; \
		type *end; \
		size_t capacity; \
	} R_VEC(name); \
	typedef void (*R_VEC_FINI(name))(type *elem, void *user); \
	typedef int (*R_VEC_CMP(name))(type *a, type *b); \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, init)(R_VEC(name) *vec) { \
		r_return_if_fail (vec); \
		memset (vec, 0, sizeof (R_VEC(name))); \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE R_VEC(name) *R_VEC_FUNC(name, new)() { \
		R_VEC(name) *vec = R_NEW (R_VEC(name)); \
		if (R_LIKELY (vec)) { \
			R_VEC_FUNC(name, init) (vec); \
		} \
		return vec; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, swap)(R_VEC(name) *vec_a, R_VEC(name) *vec_b) { \
		r_return_if_fail (vec_a && vec_b); \
		if (R_LIKELY (vec_a != vec_b)) { \
			const R_VEC(name) tmp = *vec_a; \
			*vec_a = *vec_b; \
			*vec_b = tmp; \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, clear)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user) { \
		r_return_if_fail (vec); \
		if (fini_fn) { \
			type *iter; \
			R_VEC_FOREACH (vec, iter) { \
				fini_fn (iter, user); \
			} \
		} \
		vec->end = vec->start; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, fini)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user) { \
		r_return_if_fail (vec); \
		if (fini_fn) { \
			type *iter; \
			R_VEC_FOREACH (vec, iter) { \
				fini_fn (iter, user); \
			} \
		} \
		R_FREE (vec->start); \
		vec->end = NULL; \
		vec->capacity = 0; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, free)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user) { \
		if (vec) { \
			R_VEC_FUNC(name, fini) (vec, fini_fn, user); \
			free (vec); \
		} \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE size_t R_VEC_FUNC(name, length)(const R_VEC(name) *vec) { \
		r_return_val_if_fail (vec, 0); \
		return vec->end - vec->start; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE size_t R_VEC_FUNC(name, capacity)(const R_VEC(name) *vec) { \
		r_return_val_if_fail (vec, 0); \
		return vec->capacity; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE bool R_VEC_FUNC(name, empty)(const R_VEC(name) *vec) { \
		r_return_val_if_fail (vec, false); \
		return vec->start == vec->end; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(name, start_iter)(const R_VEC(name) *vec) { \
		r_return_val_if_fail (vec, NULL); \
		return vec->start; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(name, end_iter)(const R_VEC(name) *vec) { \
		r_return_val_if_fail (vec, NULL); \
		return vec->end; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(name, at)(const R_VEC(name) *vec, size_t index) { \
		r_return_val_if_fail (vec, NULL); \
		if (R_LIKELY (index < R_VEC_FUNC(name, length) (vec))) { \
			return vec->start + index; \
		} \
		return NULL; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE R_VEC(name) *R_VEC_FUNC(name, clone)(const R_VEC(name) *vec) { \
		r_return_val_if_fail (vec, NULL); \
		const size_t capacity = R_VEC_FUNC(name, capacity) (vec); \
		type *buf = malloc (capacity * sizeof (type)); \
		if (R_LIKELY (buf)) { \
			R_VEC(name) *cloned_vec = malloc (sizeof (R_VEC(name))); \
			if (R_LIKELY (cloned_vec)) { \
				const size_t num_elems = R_VEC_FUNC(name, length) (vec); \
				memcpy (buf, vec->start, num_elems * sizeof (type)); \
				cloned_vec->start = buf; \
				cloned_vec->end = buf + num_elems; \
				cloned_vec->capacity = capacity; \
				return cloned_vec; \
			} \
			free (buf); \
		} \
		return NULL; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, reserve)(R_VEC(name) *vec, size_t new_capacity) { \
		r_return_if_fail (vec); \
		if (new_capacity > R_VEC_FUNC(name, capacity) (vec)) { \
			type *buf = realloc (vec->start, new_capacity * sizeof (type)); \
			if (R_LIKELY (buf)) { \
				const size_t num_elems = R_VEC_FUNC(name, length) (vec); \
				vec->start = buf; \
				vec->end = buf + num_elems; \
				vec->capacity = new_capacity; \
			} \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, shrink_to_fit)(R_VEC(name) *vec) { \
		r_return_if_fail (vec); \
		const size_t num_elems = R_VEC_FUNC(name, length) (vec); \
		if (num_elems != R_VEC_FUNC(name, capacity) (vec)) { \
			type *buf = realloc (vec->start, num_elems * sizeof (type)); \
			if (R_LIKELY (buf)) { \
				vec->start = buf; \
				vec->end = buf + num_elems; \
				vec->capacity = num_elems; \
			} \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, push_back)(R_VEC(name) *vec, type *value) { \
		r_return_if_fail (vec && value); \
		const size_t num_elems = R_VEC_FUNC(name, length) (vec); \
		const size_t capacity = R_VEC_FUNC(name, capacity) (vec); \
		if (R_UNLIKELY (num_elems == capacity)) { \
			const size_t new_capacity = capacity == 0 ? 8 : capacity * 2; \
			R_VEC_FUNC(name, reserve) (vec, new_capacity); \
		} \
		*vec->end = *value; \
		vec->end++; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, push_front)(R_VEC(name) *vec, type *value) { \
		r_return_if_fail (vec && value); \
		const size_t num_elems = R_VEC_FUNC(name, length) (vec); \
		const size_t capacity = R_VEC_FUNC(name, capacity) (vec); \
		if (R_UNLIKELY (num_elems == capacity)) { \
			const size_t new_capacity = capacity == 0 ? 8 : capacity * 2; \
			R_VEC_FUNC(name, reserve) (vec, new_capacity); \
		} \
		memmove (vec->start + 1, vec->start, num_elems * sizeof (type)); \
		*vec->start = *value; \
		vec->end++; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, append)(R_VEC(name) *vec, R_VEC(name) *values) { \
		r_return_if_fail (vec && values); \
		const size_t num_elems = R_VEC_FUNC(name, length) (vec); \
		const size_t capacity = R_VEC_FUNC(name, capacity) (vec); \
		const size_t num_values = R_VEC_FUNC(name, length) (values); \
		const size_t total_count = num_elems + num_values; \
		if (total_count >= capacity) { \
			/* TODO compute new_capacity without loop? */ \
			size_t new_capacity = capacity * 2; \
			while (new_capacity < total_count) { \
				new_capacity = new_capacity * 2; \
			} \
			R_VEC_FUNC(name, reserve) (vec, new_capacity); \
		} \
		memcpy (vec->end, values->start, num_values * sizeof (type)); \
		vec->end += num_values; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, remove)(R_VEC(name) *vec, size_t index, R_VEC_FINI(name) fini_fn, void *user) { \
		r_return_if_fail (vec && vec->start != vec->end && index < vec->start - vec->end); \
		type *ptr = R_VEC_FUNC(name, at) (vec, index); \
		const size_t num_elems_after = vec->end - ptr; \
		if (fini_fn) { \
			fini_fn (ptr, user); \
		} \
		memmove (ptr, ptr + 1, (num_elems_after - 1) * sizeof (type)); \
		vec->end--; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, pop_front)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user) { \
		R_VEC_FUNC(name, remove) (vec, 0, fini_fn, user); \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(name, pop_back)(R_VEC(name) *vec, R_VEC_FINI(name) fini_fn, void *user) { \
		r_return_if_fail (vec && vec->start != vec->end); \
		type *last = vec->end - 1; \
		if (fini_fn) { \
			fini_fn (last, user); \
		} \
		vec->end = last; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE size_t R_VEC_FUNC(name, lower_bound)(R_VEC(name) *vec, type *value, R_VEC_CMP(name) cmp_fn) { \
		r_return_val_if_fail (vec && value && cmp_fn, 0); \
		size_t end_pos = R_VEC_FUNC(name, length) (vec); \
		size_t pos; \
		for (pos = 0; pos < end_pos; ) { \
			size_t middle = pos + ((end_pos - pos) >> 1); \
			if (cmp_fn (value, R_VEC_FUNC(name, at) (vec, middle)) > 0) { \
				pos = middle + 1; \
			} else { \
				end_pos = middle; \
			} \
		} \
		return pos; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE size_t R_VEC_FUNC(name, upper_bound)(R_VEC(name) *vec, type *value, R_VEC_CMP(name) cmp_fn) { \
		r_return_val_if_fail (vec && value && cmp_fn, 0); \
		size_t end_pos = R_VEC_FUNC(name, length) (vec); \
		size_t pos; \
		for (pos = 0; pos < end_pos; ) { \
			size_t middle = pos + ((end_pos - pos) >> 1); \
			if (cmp_fn (value, R_VEC_FUNC(name, at) (vec, middle)) < 0) { \
				end_pos = middle; \
			} else { \
				pos = middle + 1; \
			} \
		} \
		return pos; \
	}

#ifdef __cplusplus
}
#endif

#endif
