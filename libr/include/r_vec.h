#ifndef R2_VEC_H
#define R2_VEC_H

#include <r_util/r_assert.h>
#include <r_types.h>

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
 * 1. Use the R_VEC_TYPE or R_VEC_TYPE_WITH_FINI macro to generate the vector
 *    implementation for a certain type. The R_VEC_TYPE_WITH_FINI should only
 *    be used for types that require a finalizer function (in other words, if
 *    they need to free memory).
 * 2. Call the functions from the API (described below), e.g. MyVector_init (&vec).
 *    Note that these are auto-generated with the macro in step 1.
 * 3. Do not access the fields in the vector struct directly, instead always use the following helper macros to avoid future breakage:
 *    R_VEC_START_ITER, R_VEC_END_ITER, R_VEC_CAPACITY.
 *
 * Vector API:
 * - void R_VEC_FUNC(vec_type, init)(vec_type *vec): Initializes an empty vector.
 * - vec_type *R_VEC_FUNC(vec_type, new)(): Allocates a new empty vector on the heap.
 * - void R_VEC_FUNC(vec_type, swap)(vec_type *vec_a, vec_type *vec_b): Swaps 2 vectors.
 * - void R_VEC_FUNC(vec_type, clear)(vec_type *vec):
 *   Clears the vector by calling fini_fn for each element (if provided). The size is set to 0,
 *   but the capacity remains the same (no allocation is freed).
 * - void R_VEC_FUNC(vec_type, fini)(vec_type *vec):
 *   Clears the vector by calling fini_fn for each element (if provided). Also frees up all memory
 *   used by the vector elements.
 * - void R_VEC_FUNC(vec_type, free)(vec_type *vec):
 *   Similar to R_VEC_FUNC(vec_type, fini), but also frees the vector itself.
 * - ut64 R_VEC_FUNC(vec_type, length)(const vec_type *vec): Returns number of elements
 *   in the vector.
 * - bool R_VEC_FUNC(vec_type, empty)(const vec_type *vec): Returns a boolean value indicating
 *   if the vector is empty or not.
 * - type *R_VEC_FUNC(vec_type, at)(const vec_type *vec, ut64 index): Returns a pointer to an
 *   element in the vector. Note that this can be used for reading or writing from/to the element,
 *   but not deleting (see the pop and remove functions for this).
 * - type *R_VEC_FUNC(vec_type, last)(const vec_type *vec): Returns a pointer to the last element
 *   in the vector. Note that this can be used for reading or writing from/to the element, but not
 *   deleting (see the pop and remove functions for this). Returns NULL if the vector is empty.
 * - type *R_VEC_FUNC(vec_type, find)(const vec_type *vec, void *value, R_VEC_FIND_CMP(vec_type) cmp_fn):
 *   Searches for the first value in the vector that is equal (compare returns 0) to the value passed in.
 *   Otherwise returns NULL.
 * - type *R_VEC_FUNC(vec_type, find_if_not)(const vec_type *vec, void *value, R_VEC_FIND_CMP(vec_type) cmp_fn):
 *   Searches for the first value in the vector that is NOT equal (compare returns != 0) to the value
 *   passed in. Otherwise returns NULL.
 * - ut64 R_VEC_FUNC(vec_type, find_index)(const vec_type *vec, void *value, R_VEC_FIND_CMP(vec_type) cmp_fn):
 *   Searches for the index of the first value in the vector that is equal (compare returns 0) to the
 *   value passed in. Otherwise returns UT64_MAX.
 * - vec_type *R_VEC_FUNC(vec_type, clone)(const vec_type *vec): Creates a shallow clone of a vector.
 * - bool R_VEC_FUNC(vec_type, reserve)(vec_type *vec, ut64 new_capacity): Ensures the vector has
 *   atleast a capacity of "new_capacity". Returns true on success, otherwise false.
 * - void R_VEC_FUNC(vec_type, shrink_to_fit)(vec_type *vec): Shrinks the vector to exactly fit the
 *   current number of elements it contains.
 * - void R_VEC_FUNC(vec_type, push_back)(vec_type *vec, type const *value): Appends a single element to
 *   the end of the vector.
 * - type *R_VEC_FUNC(vec_type, emplace_back)(vec_type *vec): Returns a pointer to a new uninitialized
 *   element at the back of the vector. The pointer must be filled with data afterwards, or it can lead to
 *   undefined behavior!
 * - void R_VEC_FUNC(vec_type, push_front)(vec_type *vec, type *value): Prepends a single element to
 *   the front of the vector. All following elements are shifted one place. Note that "push_back"
 *   should be preferred, since it is much more efficient.
 * - type *R_VEC_FUNC(vec_type, emplace_front)(vec_type *vec): Returns a pointer to a new uninitialized
 *   element at the front of the vector. The pointer must be filled afterwards with data, or it can lead to
 *   undefined behavior! Note that "emplace_back" is preferred, since it is much more efficient.
 * - void R_VEC_FUNC(vec_type, append)(vec_type *vec, vec_type *values): Appends the elements of
 *   the second vector to the first. Note that only a shallow copy is made for each element.
 * - void R_VEC_FUNC(vec_type, remove)(vec_type *vec, ut64 index):
 *   Calls the fini_fn on the Nth element of the vector (if provided), and then removes it.
 *   All subsequent elements are shifted 1 toward the beginning of the vector.
 * - void R_VEC_FUNC(vec_type, pop_front)(vec_type *vec):
 *   Calls the fini_fn on the first element of the vector (if provided), and then removes it.
 *   All subsequent elements are shifted 1 toward the beginning of the vector. Note that this is
 *   much slower than "pop_back".
 * - void R_VEC_FUNC(vec_type, pop_back)(vec_type *vec):
 *   Calls the fini_fn on the last element of the vector (if provided), and then removes it.
 * - void R_VEC_FUNC(vec_type, erase_back)(vec_type *vec, type *iter):
 *   Removes all elements from the back of the vector starting from "iter". Does not shrink the vector.
 * - ut64 R_VEC_FUNC(vec_type, lower_bound)(vec_type *vec, type *value, R_VEC_CMP(vec_type) cmp_fn):
 *   Calculates the lower bound of a value in a vector. Returns the index to the element containing
 *   the lower bound.
 * - ut64 R_VEC_FUNC(vec_type, upper_bound)(vec_type *vec, type *value, R_VEC_CMP(vec_type) cmp_fn):
 *   Calculates the upper bound of a value in a vector. Returns the index to the element containing
 *   the upper bound.
 * - type *R_VEC_FUNC(vec_type, partition)(vec_type *vec, R_VEC_CMP(vec_type) cmp_fn):
 *   Partitions the vector such that elements for which the compare function returns true come first,
 *   followed by elements for which predicate returns false. Returns a pointer to the first element
 *   in the vector for which the predicate returns false.
 * - void R_VEC_FUNC(vec_type, sort)(vec_type *vec, R_VEC_CMP(vec_type) cmp_fn):
 *   Sorts the vector in place using a comparison function.
 * - void R_VEC_FUNC(vec_type, uniq)(vec_type *vec, R_VEC_CMP(vec_type) cmp_fn):
 *   Removes duplicates from the vector. The vector has to be sorted before this function is called!
 *   Calls the fini_fn for every removed duplicate element (if provided). Does not shrink the vector.
 */

// Helper macro for accessing the start iterator of a vector.
// Returns a pointer to the start of the elements in the vector.
// Use this macro instead of directly accessing the field, to avoid future breakage.
#define R_VEC_START_ITER(vec) (vec)->_start

// Helper macro for accessing the end iterator of a vector.
// Returns a pointer to one element PAST the end of the last filled in element in the vector.
// Use this macro instead of directly accessing the field, to avoid future breakage.
#define R_VEC_END_ITER(vec) (vec)->_end

// Helper macro for accessing the capacity of a vector. Returns the max number
// of elements that can fit in the vector before a re-allocation needs to be
// performed. Use this macro instead of directly accessing the field, to avoid future breakage.
#define R_VEC_CAPACITY(vec) (vec)->_capacity

// Helper macros for doing a foreach-style loop over the elements of a vector.
#define R_VEC_FOREACH(vec, iter) for (iter = (vec)->_start; iter != (vec)->_end; iter++)
#define R_VEC_FOREACH_PREV(vec, iter) if ((vec)->_start != (vec)->_end) for (iter = (vec)->_end - 1; iter >= (vec)->_start; iter--)

#define R_CONCAT_INNER(a, b) a ## b
#define R_CONCAT(a, b) R_CONCAT_INNER(a, b)

// Helper macro for referring to functions that can deep copy types stored in a "vec_type".
#define R_VEC_COPY(vec_type) R_CONCAT(vec_type, Copy)

// Helper macros for referring to comparison functions of types stored in a "vec_type".
#define R_VEC_CMP(vec_type) R_CONCAT(vec_type, Compare)
#define R_VEC_FIND_CMP(vec_type) R_CONCAT(vec_type, FindCompare)

// Helper macro for referring to functions of a "vec_type". It is only used internally
// to simplify some of the macro code.
#define R_VEC_FUNC(vec_type, fn) R_CONCAT(R_CONCAT(vec_type, _), fn)

// Helper macro for forward declaring a vector type. Useful for when you want
// to use a vector in a header file that is used in a lot of places without
// generating all the code for the implementation (at the cost of a pointer-indirection).
#define R_VEC_FORWARD_DECLARE(vec_type) \
	typedef struct R_CONCAT(R_CONCAT(r_vec_, vec_type), _t) vec_type

#ifdef _MSC_VER
#define R_MAYBE_UNUSED
#else
#define R_MAYBE_UNUSED __attribute__((unused))
#endif

// Hack / Helper macro for conditional code generation.
#define R_MAYBE_GENERATE(condition, code) R_MAYBE_GENERATE##condition(code)
#define R_MAYBE_GENERATE1(code) code
#define R_MAYBE_GENERATE0(code)

// The main macros that generate the implementation for a vector.
// This should only be used once per type in a single compilation unit,
// otherwise you will end up with duplicate symbols.
//
// Because of the way headers work in C, you should try to avoid using this in
// header files, or the pre-processor will include the generated code in each
// of the files that includes this header file. If you want to avoid this,
// you can forward declare a vector type (at the cost of a pointer-indirection).
#define R_VEC_TYPE(vec_type, type) R_VEC_TYPE_INNER(vec_type, type, _, 0)
#define R_VEC_TYPE_WITH_FINI(vec_type, type, fini_fn) R_VEC_TYPE_INNER(vec_type, type, fini_fn, 1)

#define R_VEC_TYPE_INNER(vec_type, type, fini_fn, has_fini) \
	typedef struct R_ALIGNED(16) r_vec_ ## vec_type ## _t { \
		type *_start; \
		type *_end; \
		size_t _capacity; \
	} vec_type; \
	typedef void (*R_VEC_COPY(vec_type))(type *dst, type const *src); \
	typedef int (*R_VEC_CMP(vec_type))(type const *a, type const *b); \
	typedef int (*R_VEC_FIND_CMP(vec_type))(type const *a, const void *b); \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, init)(vec_type *vec) { \
		R_RETURN_IF_FAIL (vec); \
		memset (vec, 0, sizeof (vec_type)); \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE vec_type *R_VEC_FUNC(vec_type, new)(void) { \
		vec_type *vec = R_NEW (vec_type); \
		if (R_LIKELY (vec)) { \
			R_VEC_FUNC(vec_type, init) (vec); \
		} \
		return vec; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, swap)(vec_type *vec_a, vec_type *vec_b) { \
		R_RETURN_IF_FAIL (vec_a && vec_b); \
		if (R_LIKELY (vec_a != vec_b)) { \
			const vec_type tmp = *vec_a; \
			*vec_a = *vec_b; \
			*vec_b = tmp; \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, clear)(vec_type *vec) { \
		R_RETURN_IF_FAIL (vec); \
		R_MAYBE_GENERATE(has_fini, \
			type *iter; \
			R_VEC_FOREACH (vec, iter) { \
				fini_fn (iter); \
			} \
		); \
		vec->_end = vec->_start; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, fini)(vec_type *vec) { \
		R_RETURN_IF_FAIL (vec); \
		R_MAYBE_GENERATE(has_fini, \
			type *iter; \
			R_VEC_FOREACH (vec, iter) { \
				fini_fn (iter); \
			} \
		); \
		R_FREE (vec->_start); \
		vec->_end = NULL; \
		vec->_capacity = 0; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, free)(vec_type *vec) { \
		if (vec) { \
			R_VEC_FUNC(vec_type, fini) (vec); \
			free (vec); \
		} \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE ut64 R_VEC_FUNC(vec_type, length)(const vec_type *vec) { \
		R_RETURN_VAL_IF_FAIL (vec, 0); \
		return vec->_start ? (ut64)(vec->_end - vec->_start) : 0; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE bool R_VEC_FUNC(vec_type, empty)(const vec_type *vec) { \
		R_RETURN_VAL_IF_FAIL (vec, false); \
		return !vec->_start || vec->_start == vec->_end; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(vec_type, at)(const vec_type *vec, ut64 index) { \
		R_RETURN_VAL_IF_FAIL (vec, NULL); \
		if (R_LIKELY (index < R_VEC_FUNC(vec_type, length) (vec))) { \
			return vec->_start + index; \
		} \
		return NULL; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(vec_type, last)(const vec_type *vec) { \
		R_RETURN_VAL_IF_FAIL (vec, NULL); \
		if (R_UNLIKELY (vec->_start == vec->_end)) { \
			return NULL; \
		} \
		return vec->_end - 1; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(vec_type, find)(const vec_type *vec, void *value, R_VEC_FIND_CMP(vec_type) cmp_fn) { \
		R_RETURN_VAL_IF_FAIL (vec, NULL); \
		type *val; \
		R_VEC_FOREACH (vec, val) { \
			if (!cmp_fn (val, value)) { \
				return val; \
			} \
		} \
		return NULL; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(vec_type, find_if_not)(const vec_type *vec, void *value, R_VEC_FIND_CMP(vec_type) cmp_fn) { \
		R_RETURN_VAL_IF_FAIL (vec && value, NULL); \
		type *val; \
		R_VEC_FOREACH (vec, val) { \
			if (cmp_fn (val, value)) { \
				return val; \
			} \
		} \
		return NULL; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE ut64 R_VEC_FUNC(vec_type, find_index)(const vec_type *vec, void *value, R_VEC_FIND_CMP(vec_type) cmp_fn) { \
		R_RETURN_VAL_IF_FAIL (vec && value, UT64_MAX); \
		ut64 index = 0; \
		type *val; \
		R_VEC_FOREACH (vec, val) { \
			if (!cmp_fn (val, value)) { \
				return index; \
			} \
			index++; \
		} \
		return UT64_MAX; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE vec_type *R_VEC_FUNC(vec_type, clone)(const vec_type *vec) { \
		R_RETURN_VAL_IF_FAIL (vec, NULL); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		type *buf = (type *)malloc (capacity * sizeof (type)); \
		if (R_LIKELY (buf)) { \
			vec_type *cloned_vec = (vec_type *)malloc (sizeof (vec_type)); \
			if (R_LIKELY (cloned_vec)) { \
				const ut64 num_elems = R_VEC_FUNC(vec_type, length) (vec); \
				memcpy (buf, vec->_start, num_elems * sizeof (type)); \
				cloned_vec->_start = buf; \
				cloned_vec->_end = buf + num_elems; \
				cloned_vec->_capacity = capacity; \
				return cloned_vec; \
			} \
			free (buf); \
		} \
		return NULL; \
	} \
	static inline R_MAYBE_UNUSED bool R_VEC_FUNC(vec_type, reserve)(vec_type *vec, ut64 new_capacity) { \
		R_RETURN_VAL_IF_FAIL (vec, false); \
		if (new_capacity > R_VEC_CAPACITY (vec)) { \
			const ut64 num_elems = R_VEC_FUNC (vec_type, length) (vec); \
			type *buf = (type *)realloc (vec->_start, new_capacity * sizeof (type)); \
			const bool is_success = buf != NULL; \
			if (R_LIKELY (is_success)) { \
				vec->_start = buf; \
				vec->_end = buf + num_elems; \
				vec->_capacity = new_capacity; \
			} \
			return is_success; \
		} \
		return true; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, shrink_to_fit)(vec_type *vec) { \
		R_RETURN_IF_FAIL (vec); \
		const ut64 num_elems = R_VEC_FUNC (vec_type, length) (vec); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		if (num_elems != capacity) { \
			if (num_elems == 0) { \
				free (vec->_start); \
				memset (vec, 0, sizeof (vec_type)); \
			} else { \
				type *buf = (type *)realloc (vec->_start, num_elems * sizeof (type)); \
				if (R_LIKELY (buf)) { \
					vec->_start = buf; \
					vec->_end = buf + num_elems; \
					vec->_capacity = num_elems; \
				} \
			} \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, push_back)(vec_type *vec, type const *value) { \
		R_RETURN_IF_FAIL (vec && value); \
		const ut64 num_elems = R_VEC_FUNC(vec_type, length) (vec); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		if (R_UNLIKELY (num_elems == capacity)) { \
			const ut64 new_capacity = capacity == 0 ? 8 : capacity * 2; \
			R_VEC_FUNC(vec_type, reserve) (vec, new_capacity); \
		} \
		*vec->_end = *value; \
		vec->_end++; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(vec_type, emplace_back)(vec_type *vec) { \
		R_RETURN_VAL_IF_FAIL (vec, NULL); \
		const ut64 num_elems = R_VEC_FUNC(vec_type, length) (vec); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		if (R_UNLIKELY (num_elems == capacity)) { \
			const ut64 new_capacity = capacity == 0 ? 8 : capacity * 2; \
			R_VEC_FUNC(vec_type, reserve) (vec, new_capacity); \
		} \
		type *ptr = vec->_end; \
		vec->_end++; \
		return ptr; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, push_front)(vec_type *vec, type *value) { \
		R_RETURN_IF_FAIL (vec && value); \
		const ut64 num_elems = R_VEC_FUNC(vec_type, length) (vec); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		if (R_UNLIKELY (num_elems == capacity)) { \
			const ut64 new_capacity = capacity == 0 ? 8 : capacity * 2; \
			R_VEC_FUNC(vec_type, reserve) (vec, new_capacity); \
		} \
		memmove (vec->_start + 1, vec->_start, num_elems * sizeof (type)); \
		*vec->_start = *value; \
		vec->_end++; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE type *R_VEC_FUNC(vec_type, emplace_front)(vec_type *vec) { \
		R_RETURN_VAL_IF_FAIL (vec, NULL); \
		const ut64 num_elems = R_VEC_FUNC(vec_type, length) (vec); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		if (R_UNLIKELY (num_elems == capacity)) { \
			const ut64 new_capacity = capacity == 0 ? 8 : capacity * 2; \
			R_VEC_FUNC(vec_type, reserve) (vec, new_capacity); \
		} \
		memmove (vec->_start + 1, vec->_start, num_elems * sizeof (type)); \
		vec->_end++; \
		return vec->_start; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, append)(vec_type *vec, const vec_type *values, R_VEC_COPY(vec_type) copy_fn) { \
		R_RETURN_IF_FAIL (vec && values); \
		const ut64 num_elems = R_VEC_FUNC(vec_type, length) (vec); \
		const ut64 capacity = R_VEC_CAPACITY (vec); \
		const ut64 num_values = R_VEC_FUNC(vec_type, length) (values); \
		const ut64 total_count = num_elems + num_values; \
		if (total_count > capacity) { \
			R_VEC_FUNC(vec_type, reserve) (vec, total_count); \
		} \
		if (copy_fn) { \
			type const *src; \
			R_VEC_FOREACH (values, src) { \
				type *dst = R_VEC_FUNC(vec_type, emplace_back) (vec); \
				copy_fn (dst, src); \
			} \
		} else { \
			memcpy (vec->_end, values->_start, num_values * sizeof (type)); \
			vec->_end += num_values; \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, remove)(vec_type *vec, ut64 index) { \
		R_RETURN_IF_FAIL (vec && vec->_start != vec->_end && index < (ut64)(size_t)(vec->_end - vec->_start)); \
		type *ptr = R_VEC_FUNC(vec_type, at) (vec, index); \
		const ut64 num_elems_after = vec->_end - ptr; \
		R_MAYBE_GENERATE(has_fini, fini_fn (ptr)); \
		memmove (ptr, ptr + 1, (num_elems_after - 1) * sizeof (type)); \
		vec->_end--; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, pop_front)(vec_type *vec) { \
		R_VEC_FUNC(vec_type, remove) (vec, 0); \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, pop_back)(vec_type *vec) { \
		R_RETURN_IF_FAIL (vec && vec->_start != vec->_end); \
		type *last = vec->_end - 1; \
		R_MAYBE_GENERATE(has_fini, fini_fn (last)); \
		vec->_end = last; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, erase_back)(vec_type *vec, type *iter) { \
		R_RETURN_IF_FAIL (vec && iter >= vec->_start && iter <= vec->_end); \
		if (iter == vec->_end) { \
			return; \
		} \
		R_MAYBE_GENERATE(has_fini, \
			type *start; \
			for (start = iter; start != vec->_end; start++) { \
				fini_fn (start); \
			} \
		); \
		vec->_end = iter; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE ut64 R_VEC_FUNC(vec_type, lower_bound)(vec_type *vec, type *value, R_VEC_CMP(vec_type) cmp_fn) { \
		R_RETURN_VAL_IF_FAIL (vec && value && cmp_fn, 0); \
		ut64 end_pos = R_VEC_FUNC(vec_type, length) (vec); \
		ut64 pos; \
		for (pos = 0; pos < end_pos; ) { \
			ut64 middle = pos + ((end_pos - pos) >> 1); \
			if (cmp_fn (value, R_VEC_FUNC(vec_type, at) (vec, middle)) > 0) { \
				pos = middle + 1; \
			} else { \
				end_pos = middle; \
			} \
		} \
		return pos; \
	} \
	static inline R_MAYBE_UNUSED R_MUSTUSE ut64 R_VEC_FUNC(vec_type, upper_bound)(vec_type *vec, type *value, R_VEC_CMP(vec_type) cmp_fn) { \
		R_RETURN_VAL_IF_FAIL (vec && value && cmp_fn, 0); \
		ut64 end_pos = R_VEC_FUNC(vec_type, length) (vec); \
		ut64 pos; \
		for (pos = 0; pos < end_pos; ) { \
			ut64 middle = pos + ((end_pos - pos) >> 1); \
			if (cmp_fn (value, R_VEC_FUNC(vec_type, at) (vec, middle)) < 0) { \
				end_pos = middle; \
			} else { \
				pos = middle + 1; \
			} \
		} \
		return pos; \
	} \
	static inline R_MAYBE_UNUSED type *R_VEC_FUNC(vec_type, partition)(vec_type *vec, void *user, R_VEC_FIND_CMP(vec_type) cmp_fn) { \
		R_RETURN_VAL_IF_FAIL (vec && cmp_fn, vec->_start); \
		type *first = R_VEC_FUNC(vec_type, find) (vec, user, cmp_fn); \
		if (first == NULL) { \
			return vec->_start; \
		} \
		type *next; \
		for (next = first + 1; next != vec->_end; next++) { \
			if (cmp_fn (next, user)) { \
				type tmp = *next; \
				*next = *first; \
				*first = tmp; \
				first++; \
			} \
		} \
		return first; \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, sort)(vec_type *vec, R_VEC_CMP(vec_type) cmp_fn) { \
		R_RETURN_IF_FAIL (vec && cmp_fn); \
		if (!R_VEC_FUNC(vec_type, empty) (vec)) { \
			qsort (vec->_start, R_VEC_FUNC(vec_type, length) (vec), sizeof (type), \
				(int (*)(const void *, const void *)) cmp_fn); \
		} \
	} \
	static inline R_MAYBE_UNUSED void R_VEC_FUNC(vec_type, uniq)(vec_type *vec, R_VEC_CMP(vec_type) cmp_fn) { \
		R_RETURN_IF_FAIL (vec && cmp_fn); \
		if (vec->_start == vec->_end) { \
			return; \
		} \
		type *current = vec->_start; \
		type *iter = current; \
		while (++current != vec->_end) { \
			if (cmp_fn (iter, current) && ++iter != current) { \
				type tmp = *current; \
				*current = *iter; \
				*iter = tmp; \
			} \
		} \
		iter++; \
		R_MAYBE_GENERATE(has_fini, \
			type *fini_iter; \
			for (fini_iter = iter; fini_iter != vec->_end; fini_iter++) { \
				fini_fn (fini_iter); \
			} \
		); \
		vec->_end = iter; \
	}

#ifdef __cplusplus
}
#endif

#endif
