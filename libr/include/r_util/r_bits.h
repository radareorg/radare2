/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_BITS_H
#define R_BITS_H

#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Centralized portable bit helpers. Use these instead of __builtin_*
 * directly so non-GCC/clang toolchains (MSVC, TCC) keep working. */

#if defined(__GNUC__) || defined(__clang__)
#define R_HAVE_BUILTIN_BITS 1
#else
#define R_HAVE_BUILTIN_BITS 0
#endif

static inline int r_bits_popcount32(ut32 x) {
#if R_HAVE_BUILTIN_BITS
	return __builtin_popcount (x);
#else
	x = x - ((x >> 1) & 0x55555555U);
	x = (x & 0x33333333U) + ((x >> 2) & 0x33333333U);
	return (int)((((x + (x >> 4)) & 0x0F0F0F0FU) * 0x01010101U) >> 24);
#endif
}

static inline int r_bits_popcount64(ut64 x) {
#if R_HAVE_BUILTIN_BITS
	return __builtin_popcountll ((unsigned long long)x);
#else
	x = x - ((x >> 1) & 0x5555555555555555ULL);
	x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
	x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
	return (int)((x * 0x0101010101010101ULL) >> 56);
#endif
}

/* count trailing zeros: returns 32/64 when x is 0 (matching R bit-width) */
static inline int r_bits_ctz32(ut32 x) {
#if R_HAVE_BUILTIN_BITS
	return x ? __builtin_ctz (x) : 32;
#else
	int n = 0;
	if (!x) {
		return 32;
	}
	if (!(x & 0x0000FFFFU)) { n += 16; x >>= 16; }
	if (!(x & 0x000000FFU)) { n += 8;  x >>= 8; }
	if (!(x & 0x0000000FU)) { n += 4;  x >>= 4; }
	if (!(x & 0x00000003U)) { n += 2;  x >>= 2; }
	if (!(x & 0x00000001U)) { n += 1; }
	return n;
#endif
}

static inline int r_bits_ctz64(ut64 x) {
#if R_HAVE_BUILTIN_BITS
	return x ? __builtin_ctzll ((unsigned long long)x) : 64;
#else
	int n = 0;
	if (!x) {
		return 64;
	}
	if (!(x & 0xFFFFFFFFULL)) { n += 32; x >>= 32; }
	if (!(x & 0x0000FFFFULL)) { n += 16; x >>= 16; }
	if (!(x & 0x000000FFULL)) { n += 8;  x >>= 8; }
	if (!(x & 0x0000000FULL)) { n += 4;  x >>= 4; }
	if (!(x & 0x00000003ULL)) { n += 2;  x >>= 2; }
	if (!(x & 0x00000001ULL)) { n += 1; }
	return n;
#endif
}

/* count leading zeros: returns 32/64 when x is 0 */
static inline int r_bits_clz32(ut32 x) {
#if R_HAVE_BUILTIN_BITS
	return x ? __builtin_clz (x) : 32;
#else
	int n = 0;
	if (!x) {
		return 32;
	}
	if (!(x & 0xFFFF0000U)) { n += 16; x <<= 16; }
	if (!(x & 0xFF000000U)) { n += 8;  x <<= 8; }
	if (!(x & 0xF0000000U)) { n += 4;  x <<= 4; }
	if (!(x & 0xC0000000U)) { n += 2;  x <<= 2; }
	if (!(x & 0x80000000U)) { n += 1; }
	return n;
#endif
}

static inline int r_bits_clz64(ut64 x) {
#if R_HAVE_BUILTIN_BITS
	return x ? __builtin_clzll ((unsigned long long)x) : 64;
#else
	int n = 0;
	if (!x) {
		return 64;
	}
	if (!(x & 0xFFFFFFFF00000000ULL)) { n += 32; x <<= 32; }
	if (!(x & 0xFFFF000000000000ULL)) { n += 16; x <<= 16; }
	if (!(x & 0xFF00000000000000ULL)) { n += 8;  x <<= 8; }
	if (!(x & 0xF000000000000000ULL)) { n += 4;  x <<= 4; }
	if (!(x & 0xC000000000000000ULL)) { n += 2;  x <<= 2; }
	if (!(x & 0x8000000000000000ULL)) { n += 1; }
	return n;
#endif
}

#ifdef __cplusplus
}
#endif

#endif //  R_BITS_H
