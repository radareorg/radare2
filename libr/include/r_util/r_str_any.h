/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_STR_ANY_H
#define R_STR_ANY_H

#include <r_types.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *text;
	size_t length;
} RStrAnyItem;

#if defined(__GNUC__) || defined(__clang__)
#define R_STR_ANY_INLINE static inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define R_STR_ANY_INLINE static __forceinline
#else
#define R_STR_ANY_INLINE static inline
#endif

#if defined(__clang__)
#define R_STR_ANY_UNROLL _Pragma ("clang loop unroll(full)")
#elif defined(__GNUC__) && __GNUC__ >= 8
#define R_STR_ANY_UNROLL _Pragma ("GCC unroll 32")
#else
#define R_STR_ANY_UNROLL
#endif

R_STR_ANY_INLINE bool r_str_cmp_any_inline(const char *key, const RStrAnyItem *items, size_t count) {
	if (!key || !*key) {
		return false;
	}
	const size_t length = strlen (key);
	size_t i;
	R_STR_ANY_UNROLL
	for (i = 0; i < count; i++) {
		if (length == items[i].length && key[0] == items[i].text[0]
				&& !memcmp (key, items[i].text, length)) {
			return true;
		}
	}
	return false;
}

R_STR_ANY_INLINE bool r_str_prefix_any_tail(const char *key, const char *item) {
	while (*item && *item == *key) {
		item++;
		key++;
	}
	return !*item;
}

R_STR_ANY_INLINE bool r_str_startswith_any_inline(const char *key, const RStrAnyItem *items, size_t count) {
	if (!key || !*key) {
		return false;
	}
	size_t i;
	R_STR_ANY_UNROLL
	for (i = 0; i < count; i++) {
		if (items[i].length && key[0] == items[i].text[0]
				&& r_str_prefix_any_tail (key + 1, items[i].text + 1)) {
			return true;
		}
	}
	return false;
}

R_STR_ANY_INLINE bool r_str_endswith_any_inline(const char *key, const RStrAnyItem *items, size_t count) {
	if (!key || !*key) {
		return false;
	}
	const size_t length = strlen (key);
	size_t i;
	R_STR_ANY_UNROLL
	for (i = 0; i < count; i++) {
		if (length <= items[i].length) {
			const char *suffix = items[i].text + items[i].length - length;
			if (*suffix == *key && !memcmp (key, suffix, length)) {
				return true;
			}
		}
	}
	return false;
}

R_STR_ANY_INLINE bool r_str_strstr_any_inline(const char *key, const RStrAnyItem *items, size_t count) {
	if (!key || !*key) {
		return false;
	}
	const size_t length = strlen (key);
	size_t i;
	R_STR_ANY_UNROLL
	for (i = 0; i < count; i++) {
		if (length <= items[i].length) {
			const char *item = items[i].text;
			const char *end = item + items[i].length - length;
			while (item <= end) {
				if (*item == *key && !memcmp (item, key, length)) {
					return true;
				}
				item++;
			}
		}
	}
	return false;
}

#undef R_STR_ANY_UNROLL
#undef R_STR_ANY_INLINE

#ifdef __cplusplus
}
#endif

#define R_STR_ANY_ITEM(item) { "" item, sizeof ("" item) - 1 }
#define R_STR_ANY_MAP_1(item) R_STR_ANY_ITEM (item)
#define R_STR_ANY_MAP_2(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_1 (__VA_ARGS__)
#define R_STR_ANY_MAP_3(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_2 (__VA_ARGS__)
#define R_STR_ANY_MAP_4(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_3 (__VA_ARGS__)
#define R_STR_ANY_MAP_5(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_4 (__VA_ARGS__)
#define R_STR_ANY_MAP_6(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_5 (__VA_ARGS__)
#define R_STR_ANY_MAP_7(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_6 (__VA_ARGS__)
#define R_STR_ANY_MAP_8(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_7 (__VA_ARGS__)
#define R_STR_ANY_MAP_9(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_8 (__VA_ARGS__)
#define R_STR_ANY_MAP_10(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_9 (__VA_ARGS__)
#define R_STR_ANY_MAP_11(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_10 (__VA_ARGS__)
#define R_STR_ANY_MAP_12(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_11 (__VA_ARGS__)
#define R_STR_ANY_MAP_13(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_12 (__VA_ARGS__)
#define R_STR_ANY_MAP_14(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_13 (__VA_ARGS__)
#define R_STR_ANY_MAP_15(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_14 (__VA_ARGS__)
#define R_STR_ANY_MAP_16(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_15 (__VA_ARGS__)
#define R_STR_ANY_MAP_17(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_16 (__VA_ARGS__)
#define R_STR_ANY_MAP_18(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_17 (__VA_ARGS__)
#define R_STR_ANY_MAP_19(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_18 (__VA_ARGS__)
#define R_STR_ANY_MAP_20(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_19 (__VA_ARGS__)
#define R_STR_ANY_MAP_21(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_20 (__VA_ARGS__)
#define R_STR_ANY_MAP_22(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_21 (__VA_ARGS__)
#define R_STR_ANY_MAP_23(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_22 (__VA_ARGS__)
#define R_STR_ANY_MAP_24(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_23 (__VA_ARGS__)
#define R_STR_ANY_MAP_25(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_24 (__VA_ARGS__)
#define R_STR_ANY_MAP_26(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_25 (__VA_ARGS__)
#define R_STR_ANY_MAP_27(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_26 (__VA_ARGS__)
#define R_STR_ANY_MAP_28(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_27 (__VA_ARGS__)
#define R_STR_ANY_MAP_29(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_28 (__VA_ARGS__)
#define R_STR_ANY_MAP_30(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_29 (__VA_ARGS__)
#define R_STR_ANY_MAP_31(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_30 (__VA_ARGS__)
#define R_STR_ANY_MAP_32(item, ...) R_STR_ANY_ITEM (item), R_STR_ANY_MAP_31 (__VA_ARGS__)
#define R_STR_ANY_SELECT(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, \
	a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, fn, ...) fn
#define R_STR_ANY_ITEMS(...) R_STR_ANY_SELECT (__VA_ARGS__, \
	R_STR_ANY_MAP_32, R_STR_ANY_MAP_31, R_STR_ANY_MAP_30, R_STR_ANY_MAP_29, \
	R_STR_ANY_MAP_28, R_STR_ANY_MAP_27, R_STR_ANY_MAP_26, R_STR_ANY_MAP_25, \
	R_STR_ANY_MAP_24, R_STR_ANY_MAP_23, R_STR_ANY_MAP_22, R_STR_ANY_MAP_21, \
	R_STR_ANY_MAP_20, R_STR_ANY_MAP_19, R_STR_ANY_MAP_18, R_STR_ANY_MAP_17, \
	R_STR_ANY_MAP_16, R_STR_ANY_MAP_15, R_STR_ANY_MAP_14, R_STR_ANY_MAP_13, \
	R_STR_ANY_MAP_12, R_STR_ANY_MAP_11, R_STR_ANY_MAP_10, R_STR_ANY_MAP_9, \
	R_STR_ANY_MAP_8, R_STR_ANY_MAP_7, R_STR_ANY_MAP_6, R_STR_ANY_MAP_5, \
	R_STR_ANY_MAP_4, R_STR_ANY_MAP_3, R_STR_ANY_MAP_2, R_STR_ANY_MAP_1) (__VA_ARGS__)

#ifdef __cplusplus
#define R_STR_ANY_CALL(fn, key, ...) \
	([](const char *r_str_any_key) { \
		static const RStrAnyItem r_str_any_items[] = { R_STR_ANY_ITEMS (__VA_ARGS__) }; \
		return fn (r_str_any_key, r_str_any_items, R_ARRAY_SIZE (r_str_any_items)); \
	} ((key)))
#elif defined(__GNUC__) || defined(__clang__)
#define R_STR_ANY_CALL(fn, key, ...) \
	__extension__ ({ \
		static const RStrAnyItem r_str_any_items[] = { R_STR_ANY_ITEMS (__VA_ARGS__) }; \
		fn ((key), r_str_any_items, R_ARRAY_SIZE (r_str_any_items)); \
	})
#else
#define R_STR_ANY_ARRAY(...) ((const RStrAnyItem[]){ R_STR_ANY_ITEMS (__VA_ARGS__) })
#define R_STR_ANY_CALL(fn, key, ...) \
	fn ((key), R_STR_ANY_ARRAY (__VA_ARGS__), sizeof (R_STR_ANY_ARRAY (__VA_ARGS__)) / sizeof (RStrAnyItem))
#endif

// Supply 1-32 separate string literals without embedded NULs; the key is evaluated once.
// NULL/empty keys and empty literals do not match.
#define R_STR_CMP_ANY(key, ...) R_STR_ANY_CALL (r_str_cmp_any_inline, key, __VA_ARGS__)
#define R_STR_STARTSWITH_ANY(key, ...) R_STR_ANY_CALL (r_str_startswith_any_inline, key, __VA_ARGS__)
// These test whether any listed entry ends with or contains the key, respectively.
#define R_STR_ENDSWITH_ANY(key, ...) R_STR_ANY_CALL (r_str_endswith_any_inline, key, __VA_ARGS__)
#define R_STR_STRSTR_ANY(key, ...) R_STR_ANY_CALL (r_str_strstr_any_inline, key, __VA_ARGS__)

#endif

