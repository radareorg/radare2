// Copyright 2022 Google LLC
// Copyright 2024 radare2
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// THIS IS A GENERATED FILE! DO NOT EDIT DIRECTLY!
// Generated using unify.py, by concatenating, in order:
// #include "cwisstable/internal/base.h"
// #include "cwisstable/internal/bits.h"
// #include "cwisstable/internal/control_byte.h"
// #include "cwisstable/internal/capacity.h"
// #include "cwisstable/internal/probe.h"
// #include "cwisstable/internal/absl_hash.h"
// #include "cwisstable/hash.h"
// #include "cwisstable/policy.h"
// #include "cwisstable/internal/raw_table.h"
// #include "cwisstable/declare.h"

#ifndef CWISSTABLE_H_
#define CWISSTABLE_H_

#if defined(__APPLE__) && (defined(__ppc__) || defined(__powerpc__))
#define CWISS_IS_MACPPC 1
#define CWISS_THREAD_LOCAL
#else
#define CWISS_IS_MACPPC 0
#endif

#include <assert.h>
#include <limits.h>
#if !CWISS_IS_MACPPC
#include <stdalign.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #if __STDC_VERSION__ < 201112L
// This requires C11
#undef static_assert
#define static_assert(x,y)
// #endif

/// cwisstable/internal/base.h /////////////////////////////////////////////////
/// Feature detection and basic helper macros.

/// C++11 compatibility macros.
///
/// Atomic support, due to incompatibilities between C++ and C11 atomic syntax.
/// - `CWISS_ATOMIC_T(Type)` names an atomic version of `Type`. We must use this
///   instead of `_Atomic(Type)` to name an atomic type.
/// - `CWISS_ATOMIC_INC(value)` will atomically increment `value` without
///   performing synchronization. This is used as a weak entropy source
///   elsewhere.
///
/// `extern "C"` support via `CWISS_END_EXTERN` and `CWISS_END_EXTERN`,
/// which open and close an `extern "C"` block in C++ mode.
#ifdef __cplusplus
#include <atomic>

#define CWISS_BEGIN_EXTERN extern "C" {
#define CWISS_END_EXTERN }
#else
#if _MSC_VER
// #include "msvc_stdatomic.h"
#else
#if __STDC_VERSION__ >= 201112L
#include <stdatomic.h>
#else
#include "gcc_stdatomic.h"
#endif
#endif

#define CWISS_BEGIN_EXTERN
#define CWISS_END_EXTERN
#endif

/// Compiler detection macros.
///
/// The following macros are defined:
/// - `CWISS_IS_CLANG` detects Clang.
/// - `CWISS_IS_GCC` detects GCC (and *not* Clang pretending to be GCC).
/// - `CWISS_IS_MSVC` detects MSCV (and *not* clang-cl).
/// - `CWISS_IS_GCCISH` detects GCC and GCC-mode Clang.
/// - `CWISS_IS_MSVCISH` detects MSVC and clang-cl.
#ifdef __clang__
#define CWISS_IS_CLANG 1
#else
#define CWISS_IS_CLANG 0
#endif
#if defined(__GNUC__)
#define CWISS_IS_GCCISH 1
#else
#define CWISS_IS_GCCISH 0
#endif
#if defined(_MSC_VER)
#define CWISS_IS_MSVCISH 1
#else
#define CWISS_IS_MSVCISH 0
#endif
#define CWISS_IS_GCC (CWISS_IS_GCCISH && !CWISS_IS_CLANG)
#define CWISS_IS_MSVC (CWISS_IS_MSVCISH && !CWISS_IS_CLANG)

#define CWISS_PRAGMA(pragma_) _Pragma(#pragma_)

#if CWISS_IS_GCCISH
#define CWISS_GCC_PUSH CWISS_PRAGMA(GCC diagnostic push)
#define CWISS_GCC_ALLOW(w_) CWISS_PRAGMA(GCC diagnostic ignored w_)
#define CWISS_GCC_POP CWISS_PRAGMA(GCC diagnostic pop)
#else
#define CWISS_GCC_PUSH
#define CWISS_GCC_ALLOW(w_)
#define CWISS_GCC_POP
#endif

/// Atomic support, due to incompatibilities between C++ and C11 atomic syntax.
/// - `CWISS_ATOMIC_T(Type)` names an atomic version of `Type`. We must use this
///   instead of `_Atomic(Type)` to name an atomic type.
/// - `CWISS_ATOMIC_INC(value)` will atomically increment `value` without
///   performing synchronization. This is used as a weak entropy source
///   elsewhere.
///
/// MSVC, of course, being that it does not support _Atomic in C mode, forces us
/// into `volatile`. This is *wrong*, but MSVC certainly won't miscompile it any
/// worse than it would a relaxed atomic. It doesn't matter for our use of
/// atomics.
#ifdef __cplusplus
#include <atomic>
#define CWISS_ATOMIC_T(Type_) volatile std::atomic<Type_>
#define CWISS_ATOMIC_INC(val_) (val_).fetch_add(1, std::memory_order_relaxed)
#elif CWISS_IS_MSVC || CWISS_IS_MACPPC
#define CWISS_ATOMIC_T(Type_) volatile Type_
#define CWISS_ATOMIC_INC(val_) (val_ += 1)
#else
#define CWISS_ATOMIC_T(Type_) volatile _Atomic(Type_)
#define CWISS_ATOMIC_INC(val_) \
	atomic_fetch_add_explicit(&(val_), 1, memory_order_relaxed)
#endif

/// Warning control around `CWISS` symbol definitions. These macros will
/// disable certain false-positive warnings that `CWISS` definitions tend to
/// emit.
#define CWISS_BEGIN                     \
	CWISS_GCC_PUSH                        \
	CWISS_GCC_ALLOW("-Wunused-function")  \
	CWISS_GCC_ALLOW("-Wunused-parameter") \
	CWISS_GCC_ALLOW("-Wcast-qual")        \
	CWISS_GCC_ALLOW("-Wmissing-field-initializers")
#define CWISS_END CWISS_GCC_POP

/// `CWISS_HAVE_SSE2` is nonzero if we have SSE2 support.
///
/// `-DCWISS_HAVE_SSE2` can be used to override it; it is otherwise detected
/// via the usual non-portable feature-detection macros.
#ifndef CWISS_HAVE_SSE2
#if defined(__SSE2__) || \
	(CWISS_IS_MSVCISH && \
	 (defined(_M_X64) || (defined(_M_IX86) && _M_IX86_FP >= 2)))
#define CWISS_HAVE_SSE2 1
#else
#define CWISS_HAVE_SSE2 0
#endif
#endif

/// `CWISS_HAVE_SSSE2` is nonzero if we have SSSE2 support.
///
/// `-DCWISS_HAVE_SSSE2` can be used to override it; it is otherwise detected
/// via the usual non-portable feature-detection macros.
#ifndef CWISS_HAVE_SSSE3
#ifdef __SSSE3__
#define CWISS_HAVE_SSSE3 1
#else
#define CWISS_HAVE_SSSE3 0
#endif
#endif

#if CWISS_HAVE_SSE2
#include <emmintrin.h>
#endif

#if CWISS_HAVE_SSSE3
#if !CWISS_HAVE_SSE2
#error "Bad configuration: SSSE3 implies SSE2!"
#endif
#include <tmmintrin.h>
#endif

/// `CWISS_HAVE_MUL128` is nonzero if there is compiler-specific
/// intrinsics for 128-bit multiplication.
///
/// `-DCWISS_HAVE_MUL128=0` can be used to explicitly fall back onto the pure
/// C implementation.
#ifndef DCWISS_HAVE_MUL128
#if defined(__SIZEOF_INT128__) && \
	((CWISS_IS_CLANG && !CWISS_IS_MSVC) || CWISS_IS_GCC)
#define DCWISS_HAVE_MUL128 1
#else
#define DCWISS_HAVE_MUL128 0
#endif
#endif

#ifdef __aarch64__
#define USE_128_MIX 0
#elif DCWISS_HAVE_MUL128
#define USE_128_MIX 1
#else
#define USE_128_MIX 0
#endif

/// `CWISS_ALIGN` is a cross-platform `alignas()`: specifically, MSVC doesn't
/// quite believe in it.
#if CWISS_IS_MSVC
#define CWISS_alignas(align_) __declspec(align(align_))

#else
#if !CWISS_IS_MACPPC
#include <stdalign.h>
#endif

#ifdef alignas
#define CWISS_alignas(align_) alignas(align_)
#else
#define CWISS_alignas(align_) __attribute__((aligned(align_)))
#endif

#endif

#ifndef alignof
#define alignof __alignof
#endif

#ifdef _MSC_VER
#define SDB_MAYBE_UNUSED
#else
#define SDB_MAYBE_UNUSED __attribute__((unused))
#endif

/// `CWISS_HAVE_BUILTIN` will, in Clang, detect whether a Clang language
/// extension is enabled.
///
/// See https://clang.llvm.org/docs/LanguageExtensions.html.
#ifdef __has_builtin
#define CWISS_HAVE_CLANG_BUILTIN(x_) __has_builtin(x_)
#else
#define CWISS_HAVE_CLANG_BUILTIN(x_) 0
#endif

/// `CWISS_HAVE_GCC_ATTRIBUTE` detects if a particular `__attribute__(())` is
/// present.
///
/// GCC: https://gcc.gnu.org/gcc-5/changes.html
/// Clang: https://clang.llvm.org/docs/LanguageExtensions.html
#ifdef __has_attribute
#define CWISS_HAVE_GCC_ATTRIBUTE(x_) __has_attribute(x_)
#else
#define CWISS_HAVE_GCC_ATTRIBUTE(x_) 0
#endif

#ifdef __has_feature
#define CWISS_HAVE_FEATURE(x_) __has_feature(x_)
#else
#define CWISS_HAVE_FEATURE(x_) 0
#endif

/// `CWISS_THREAD_LOCAL` expands to the appropriate TLS annotation, if one is
/// available.
#if CWISS_IS_GCCISH && !CWISS_IS_MACPPC
#define CWISS_THREAD_LOCAL __thread
#elif CWISS_IS_MSVC
#define CWISS_THREAD_LOCAL
#endif

/// `CWISS_CHECK` will evaluate `cond_` and, if false, print an error and crash
/// the program.
///
/// This is like `assert()` but unconditional.
#define CWISS_CHECK(cond_, ...)                                           \
	do {                                                                    \
		if (cond_) break;                                                     \
		fprintf(stderr, "CWISS_CHECK failed at %s:%d\n", __FILE__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);                                         \
		fprintf(stderr, "\n");                                                \
		fflush(stderr);                                                       \
		abort();                                                              \
	} while (false)

/// `CWISS_DCHECK` is like `CWISS_CHECK` but is disabled by `NDEBUG`.
#ifdef NDEBUG
#define CWISS_DCHECK(cond_, ...) ((void)0)
#else
#define CWISS_DCHECK CWISS_CHECK
#endif

/// `CWISS_LIKELY` and `CWISS_UNLIKELY` provide a prediction hint to the
/// compiler to encourage branches to be scheduled in a particular way.
#if CWISS_HAVE_CLANG_BUILTIN(__builtin_expect) || CWISS_IS_GCC
#define CWISS_LIKELY(cond_) (__builtin_expect(false || (cond_), true))
#define CWISS_UNLIKELY(cond_) (__builtin_expect(false || (cond_), false))
#else
#define CWISS_LIKELY(cond_) (cond_)
#define CWISS_UNLIKELY(cond_) (cond_)
#endif

/// `CWISS_INLINE_ALWAYS` informs the compiler that it should try really hard
/// to inline a function.
#if CWISS_HAVE_GCC_ATTRIBUTE(always_inline)
#define CWISS_INLINE_ALWAYS __attribute__((always_inline))
#else
#define CWISS_INLINE_ALWAYS
#endif

/// `CWISS_INLINE_NEVER` informs the compiler that it should avoid inlining a
/// function.
#if CWISS_HAVE_GCC_ATTRIBUTE(noinline)
#define CWISS_INLINE_NEVER __attribute__((noinline))
#else
#define CWISS_INLINE_NEVER
#endif

/// `CWISS_PREFETCH` informs the compiler that it should issue prefetch
/// instructions.
#if CWISS_HAVE_CLANG_BUILTIN(__builtin_prefetch) || CWISS_IS_GCC
#define CWISS_HAVE_PREFETCH 1
#define CWISS_PREFETCH(addr_, locality_) \
	__builtin_prefetch(addr_, 0, locality_);
#else
#define CWISS_HAVE_PREFETCH 0
#define CWISS_PREFETCH(addr_, locality_) ((void)0)
#endif

/// `CWISS_HAVE_ASAN` and `CWISS_HAVE_MSAN` detect the presence of some of the
/// sanitizers.
#if defined(__SANITIZE_ADDRESS__) || CWISS_HAVE_FEATURE(address_sanitizer)
#define CWISS_HAVE_ASAN 1
#else
#define CWISS_HAVE_ASAN 0
#endif
#if defined(__SANITIZE_MEMORY__) || \
	(CWISS_HAVE_FEATURE(memory_sanitizer) && !defined(__native_client__))
#define CWISS_HAVE_MSAN 1
#else
#define CWISS_HAVE_MSAN 0
#endif

#if CWISS_HAVE_ASAN
#include <sanitizer/asan_interface.h>
#endif

#if CWISS_HAVE_MSAN
#include <sanitizer/msan_interface.h>
#endif

/// Maximally careful endianness detection.
/// Assume LITTLE_ENDIAN by default.
#if defined(__has_include)
# if __has_include(<endian.h>)
#   include <endian.h>
#   if defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN)
#     define CWISS_IS_BIG_ENDIAN 1
#   endif
# endif
#elif defined(__BYTE_ORDER__)
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#   define CWISS_IS_BIG_ENDIAN 1
# endif
#elif defined(__ppc__) || defined(__powerpc__)
# define CWISS_IS_BIG_ENDIAN 1
#elif defined(_AIX)
# define CWISS_IS_BIG_ENDIAN 1
#else
# warning "Cannot detect endianness; assuming little-endian."
#endif
#ifndef CWISS_IS_BIG_ENDIAN
# define CWISS_IS_BIG_ENDIAN 0
#endif

CWISS_BEGIN
CWISS_BEGIN_EXTERN
/// Informs a sanitizer runtime that this memory is invalid.
static inline void CWISS_PoisonMemory(const void* m, size_t s) {
#if CWISS_HAVE_ASAN
	ASAN_POISON_MEMORY_REGION(m, s);
#endif
#if CWISS_HAVE_MSAN
	__msan_poison(m, s);
#endif
	(void)m;
	(void)s;
}

/// Informs a sanitizer runtime that this memory is no longer invalid.
static inline void CWISS_UnpoisonMemory(const void* m, size_t s) {
#if CWISS_HAVE_ASAN
	ASAN_UNPOISON_MEMORY_REGION(m, s);
#endif
#if CWISS_HAVE_MSAN
	__msan_unpoison(m, s);
#endif
	(void)m;
	(void)s;
}
CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/base.h /////////////////////////////////////////////////

/// cwisstable/internal/bits.h /////////////////////////////////////////////////
/// Bit manipulation utilities.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// Counts the number of trailing zeroes in the binary representation of `x`.
CWISS_INLINE_ALWAYS
static inline uint32_t CWISS_TrailingZeroes64(uint64_t x) {
#if CWISS_HAVE_CLANG_BUILTIN(__builtin_ctzll) || CWISS_IS_GCC
#if defined( __STDC_VERSION__ ) && __STDC_VERSION__ >= 201112L
	static_assert(sizeof(unsigned long long) == sizeof(x),
			"__builtin_ctzll does not take 64-bit arg");
#endif
	return __builtin_ctzll(x);
#elif CWISS_IS_MSVC
	unsigned long result = 0;
#if defined(_M_X64) || defined(_M_ARM64)
	_BitScanForward64(&result, x);
#else
	if (((uint32_t)x) == 0) {
		_BitScanForward(&result, (unsigned long)(x >> 32));
		return result + 32;
	}
	_BitScanForward(&result, (unsigned long)(x));
#endif
	return result;
#else
	uint32_t c = 63;
	x &= ~x + 1;
	if (x & 0x00000000FFFFFFFF) c -= 32;
	if (x & 0x0000FFFF0000FFFF) c -= 16;
	if (x & 0x00FF00FF00FF00FF) c -= 8;
	if (x & 0x0F0F0F0F0F0F0F0F) c -= 4;
	if (x & 0x3333333333333333) c -= 2;
	if (x & 0x5555555555555555) c -= 1;
	return c;
#endif
}

/// Counts the number of leading zeroes in the binary representation of `x`.
CWISS_INLINE_ALWAYS
static inline uint32_t CWISS_LeadingZeroes64(uint64_t x) {
#if CWISS_HAVE_CLANG_BUILTIN(__builtin_clzll) || CWISS_IS_GCC
#if defined( __STDC_VERSION__ ) && __STDC_VERSION__ >= 201112L
	static_assert(sizeof(unsigned long long) == sizeof(x),
			"__builtin_clzll does not take 64-bit arg");
#endif
	// Handle 0 as a special case because __builtin_clzll(0) is undefined.
	return x == 0 ? 64 : __builtin_clzll(x);
#elif CWISS_IS_MSVC
	unsigned long result = 0;
#if defined(_M_X64) || defined(_M_ARM64)
	if (_BitScanReverse64(&result, x)) {
		return 63 - result;
	}
#else
	if ((x >> 32) && _BitScanReverse(&result, (unsigned long)(x >> 32))) {
		return 31 - result;
	}
	if (_BitScanReverse(&result, (unsigned long)(x))) {
		return 63 - result;
	}
#endif
	return 64;
#else
	uint32_t zeroes = 60;
	if (x >> 32) {
		zeroes -= 32;
		x >>= 32;
	}
	if (x >> 16) {
		zeroes -= 16;
		x >>= 16;
	}
	if (x >> 8) {
		zeroes -= 8;
		x >>= 8;
	}
	if (x >> 4) {
		zeroes -= 4;
		x >>= 4;
	}
	return "\4\3\2\2\1\1\1\1\0\0\0\0\0\0\0"[x] + zeroes;
#endif
}

/// Counts the number of trailing zeroes in the binary representation of `x_` in
/// a type-generic fashion.
#define CWISS_TrailingZeros(x_) (CWISS_TrailingZeroes64(x_))

/// Counts the number of leading zeroes in the binary representation of `x_` in
/// a type-generic fashion.
#define CWISS_LeadingZeros(x_) \
	(CWISS_LeadingZeroes64(x_) - \
	 (uint32_t)((sizeof(unsigned long long) - sizeof(x_)) * 8))

/// Computes the number of bits necessary to represent `x_`, i.e., the bit index
/// of the most significant one.
#define CWISS_BitWidth(x_) \
	(((uint32_t)(sizeof(x_) * 8)) - CWISS_LeadingZeros(x_))

#define CWISS_RotateLeft(x_, bits_) \
	(((x_) << bits_) | ((x_) >> (sizeof(x_) * 8 - bits_)))

/// The return type of `CWISS_Mul128`.
typedef struct {
	uint64_t lo, hi;
} CWISS_U128;

/// Computes a double-width multiplication operation.
static inline CWISS_U128 CWISS_Mul128(uint64_t a, uint64_t b) {
#ifdef __SIZEOF_INT128__
	// TODO: de-intrinsics-ize this.
	__uint128_t p = a;
	p *= b;
	return (CWISS_U128) { (uint64_t)p, (uint64_t)(p >> 64) };
#else
	/*
	 * https://stackoverflow.com/questions/25095741/how-can-i-multiply-64-bit-operands-and-get-128-bit-result-portably
	 *
	 * Fast yet simple grade school multiply that avoids
	 * 64-bit carries with the properties of multiplying by 11
	 * and takes advantage of UMAAL on ARMv6 to only need 4
	 * calculations.
	 */

	/* First calculate all of the cross products. */
	const uint64_t lo_lo = (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
	const uint64_t hi_lo = (a >> 32) * (b & 0xFFFFFFFF);
	const uint64_t lo_hi = (a & 0xFFFFFFFF) * (b >> 32);
	const uint64_t hi_hi = (a >> 32) * (b >> 32);

	/* Now add the products together. These will never overflow. */
	const uint64_t cross = (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi;
	const uint64_t high = (hi_lo >> 32) + (cross >> 32) + hi_hi;
	const uint64_t low = (cross << 32) | (lo_lo & 0xFFFFFFFF);
	CWISS_U128 result = { .lo = low, .hi = high };
	return result;
#endif
}

/// Loads an unaligned u32.
static inline uint32_t CWISS_Load32(const void* p) {
	uint32_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

/// Loads an unaligned u64.
static inline uint64_t CWISS_Load64(const void* p) {
	uint64_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

/// Reads 9 to 16 bytes from p.
static inline CWISS_U128 CWISS_Load9To16(const void* p, size_t len) {
	const unsigned char* p8 = (const unsigned char*)p;
	uint64_t lo = CWISS_Load64(p8);
	uint64_t hi = CWISS_Load64(p8 + len - 8);
	return (CWISS_U128) { lo, hi >> (128 - len * 8) };
}

/// Reads 4 to 8 bytes from p.
static inline uint64_t CWISS_Load4To8(const void* p, size_t len) {
	const unsigned char* p8 = (const unsigned char*)p;
	uint64_t lo = CWISS_Load32(p8);
	uint64_t hi = CWISS_Load32(p8 + len - 4);
	return lo | (hi << (len - 4) * 8);
}

/// Reads 1 to 3 bytes from p.
static inline uint32_t CWISS_Load1To3(const void* p, size_t len) {
	const unsigned char* p8 = (const unsigned char*)p;
	uint32_t mem0 = p8[0];
	uint32_t mem1 = p8[len / 2];
	uint32_t mem2 = p8[len - 1];
	return (mem0 | (mem1 << (len / 2 * 8)) | (mem2 << ((len - 1) * 8)));
}

/// A abstract bitmask, such as that emitted by a SIMD instruction.
///
/// Specifically, this type implements a simple bitset whose representation is
/// controlled by `width` and `shift`. `width` is the number of abstract bits in
/// the bitset, while `shift` is the log-base-two of the width of an abstract
/// bit in the representation.
///
/// For example, when `width` is 16 and `shift` is zero, this is just an
/// ordinary 16-bit bitset occupying the low 16 bits of `mask`. When `width` is
/// 8 and `shift` is 3, abstract bits are represented as the bytes `0x00` and
/// `0x80`, and it occupies all 64 bits of the bitmask.
typedef struct {
	/// The mask, in the representation specified by `width` and `shift`.
	uint64_t mask;
	/// The number of abstract bits in the mask.
	uint32_t width;
	/// The log-base-two width of an abstract bit.
	uint32_t shift;
} CWISS_BitMask;

/// Returns the index of the lowest abstract bit set in `self`.
static inline uint32_t CWISS_BitMask_LowestBitSet(const CWISS_BitMask* self) {
	return CWISS_TrailingZeros(self->mask) >> self->shift;
}

/// Returns the index of the highest abstract bit set in `self`.
static inline uint32_t CWISS_BitMask_HighestBitSet(const CWISS_BitMask* self) {
	return (uint32_t)(CWISS_BitWidth(self->mask) - 1) >> self->shift;
}

/// Return the number of trailing zero abstract bits.
static inline uint32_t CWISS_BitMask_TrailingZeros(const CWISS_BitMask* self) {
	return CWISS_TrailingZeros(self->mask) >> self->shift;
}

/// Return the number of leading zero abstract bits.
static inline uint32_t CWISS_BitMask_LeadingZeros(const CWISS_BitMask* self) {
	uint32_t total_significant_bits = self->width << self->shift;
	uint32_t extra_bits = sizeof(self->mask) * 8 - total_significant_bits;
	return (uint32_t)(CWISS_LeadingZeros(self->mask << extra_bits)) >>
		self->shift;
}

/// Iterates over the one bits in the mask.
///
/// If the mask is empty, returns `false`; otherwise, returns the index of the
/// lowest one bit in the mask, and removes it from the set.
static inline bool CWISS_BitMask_next(CWISS_BitMask* self, uint32_t* bit) {
	if (self->mask == 0) {
		return false;
	}

	*bit = CWISS_BitMask_LowestBitSet(self);
	self->mask &= (self->mask - 1);
	return true;
}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/bits.h /////////////////////////////////////////////////

/// cwisstable/internal/control_byte.h /////////////////////////////////////////
CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// Control bytes and groups: the core of SwissTable optimization.
///
/// Control bytes are bytes (collected into groups of a platform-specific size)
/// that define the state of the corresponding slot in the slot array. Group
/// manipulation is tightly optimized to be as efficient as possible.

/// A `CWISS_ControlByte` is a single control byte, which can have one of four
/// states: empty, deleted, full (which has an associated seven-bit hash) and
/// the sentinel. They have the following bit patterns:
///
/// ```
///    empty: 1 0 0 0 0 0 0 0
///  deleted: 1 1 1 1 1 1 1 0
///     full: 0 h h h h h h h  // h represents the hash bits.
/// sentinel: 1 1 1 1 1 1 1 1
/// ```
///
/// These values are specifically tuned for SSE-flavored SIMD; future ports to
/// other SIMD platforms may require choosing new values. The static_asserts
/// below detail the source of these choices.
typedef int8_t CWISS_ControlByte;
#define CWISS_kEmpty (INT8_C(-128))
#define CWISS_kDeleted (INT8_C(-2))
#define CWISS_kSentinel (INT8_C(-1))
// TODO: Wrap CWISS_ControlByte in a single-field struct to get strict-aliasing
// benefits.

#if defined( __STDC_VERSION__ ) && __STDC_VERSION__ >= 201112L
static_assert(
    (CWISS_kEmpty & CWISS_kDeleted & CWISS_kSentinel & 0x80) != 0,
    "Special markers need to have the MSB to make checking for them efficient");
static_assert(
    CWISS_kEmpty < CWISS_kSentinel && CWISS_kDeleted < CWISS_kSentinel,
    "CWISS_kEmpty and CWISS_kDeleted must be smaller than "
    "CWISS_kSentinel to make the SIMD test of IsEmptyOrDeleted() efficient");
static_assert(
    CWISS_kSentinel == -1,
    "CWISS_kSentinel must be -1 to elide loading it from memory into SIMD "
    "registers (pcmpeqd xmm, xmm)");
static_assert(CWISS_kEmpty == -128,
              "CWISS_kEmpty must be -128 to make the SIMD check for its "
              "existence efficient (psignb xmm, xmm)");
static_assert(
    (~CWISS_kEmpty & ~CWISS_kDeleted & CWISS_kSentinel & 0x7F) != 0,
    "CWISS_kEmpty and CWISS_kDeleted must share an unset bit that is not "
    "shared by CWISS_kSentinel to make the scalar test for "
    "MatchEmptyOrDeleted() efficient");
static_assert(CWISS_kDeleted == -2,
              "CWISS_kDeleted must be -2 to make the implementation of "
              "ConvertSpecialToEmptyAndFullToDeleted efficient");
#endif

/// Returns a pointer to a control byte group that can be used by empty tables.
static inline CWISS_ControlByte* CWISS_EmptyGroup(void) {
	// A single block of empty control bytes for tables without any slots
	// allocated. This enables removing a branch in the hot path of find().
	CWISS_alignas(16) static const CWISS_ControlByte kEmptyGroup[16] = {
		CWISS_kSentinel, CWISS_kEmpty, CWISS_kEmpty, CWISS_kEmpty,
		CWISS_kEmpty,    CWISS_kEmpty, CWISS_kEmpty, CWISS_kEmpty,
		CWISS_kEmpty,    CWISS_kEmpty, CWISS_kEmpty, CWISS_kEmpty,
		CWISS_kEmpty,    CWISS_kEmpty, CWISS_kEmpty, CWISS_kEmpty,
	};

	// Const must be cast away here; no uses of this function will actually write
	// to it, because it is only used for empty tables.
	return (CWISS_ControlByte*)&kEmptyGroup;
}

/// Returns a hash seed.
///
/// The seed consists of the ctrl_ pointer, which adds enough entropy to ensure
/// non-determinism of iteration order in most cases.
static inline size_t CWISS_HashSeed(const CWISS_ControlByte* ctrl) {
	// The low bits of the pointer have little or no entropy because of
	// alignment. We shift the pointer to try to use higher entropy bits. A
	// good number seems to be 12 bits, because that aligns with page size.
	return ((uintptr_t)ctrl) >> 12;
}

/// Extracts the H1 portion of a hash: the high 57 bits mixed with a per-table
/// salt.
static inline size_t CWISS_H1(size_t hash, const CWISS_ControlByte* ctrl) {
	return (hash >> 7) ^ CWISS_HashSeed(ctrl);
}

/// Extracts the H2 portion of a hash: the low 7 bits, which can be used as
/// control byte.
typedef uint8_t CWISS_h2_t;
static inline CWISS_h2_t CWISS_H2(size_t hash) { return hash & 0x7F; }

/// Returns whether `c` is empty.
static inline bool CWISS_IsEmpty(CWISS_ControlByte c) {
	return c == CWISS_kEmpty;
}

/// Returns whether `c` is full.
static inline bool CWISS_IsFull(CWISS_ControlByte c) { return c >= 0; }

/// Returns whether `c` is deleted.
static inline bool CWISS_IsDeleted(CWISS_ControlByte c) {
	return c == CWISS_kDeleted;
}

/// Returns whether `c` is empty or deleted.
static inline bool CWISS_IsEmptyOrDeleted(CWISS_ControlByte c) {
	return c < CWISS_kSentinel;
}

/// Asserts that `ctrl` points to a full control byte.
#define CWISS_AssertIsFull(ctrl)                                               \
	CWISS_CHECK((ctrl) != NULL && CWISS_IsFull(*(ctrl)),                         \
			"Invalid operation on iterator (%p/%d). The element might have " \
			"been erased, or the table might have rehashed.",                \
			(ctrl), (ctrl) ? *(ctrl) : -1)

/// Asserts that `ctrl` is either null OR points to a full control byte.
#define CWISS_AssertIsValid(ctrl)                                              \
	CWISS_CHECK((ctrl) == NULL || CWISS_IsFull(*(ctrl)),                         \
			"Invalid operation on iterator (%p/%d). The element might have " \
			"been erased, or the table might have rehashed.",                \
			(ctrl), (ctrl) ? *(ctrl) : -1)

/// Constructs a `BitMask` with the correct parameters for whichever
/// implementation of `CWISS_Group` is in use.
#define CWISS_Group_BitMask(x) \
	(CWISS_BitMask){(uint64_t)(x), CWISS_Group_kWidth, CWISS_Group_kShift};

// TODO(#4): Port this to NEON.
#if CWISS_HAVE_SSE2
// Reference guide for intrinsics used below:
//
// * __m128i: An XMM (128-bit) word.
//
// * _mm_setzero_si128: Returns a zero vector.
// * _mm_set1_epi8:     Returns a vector with the same i8 in each lane.
//
// * _mm_subs_epi8:    Saturating-subtracts two i8 vectors.
// * _mm_and_si128:    Ands two i128s together.
// * _mm_or_si128:     Ors two i128s together.
// * _mm_andnot_si128: And-nots two i128s together.
//
// * _mm_cmpeq_epi8: Component-wise compares two i8 vectors for equality,
//                   filling each lane with 0x00 or 0xff.
// * _mm_cmpgt_epi8: Same as above, but using > rather than ==.
//
// * _mm_loadu_si128:  Performs an unaligned load of an i128.
// * _mm_storeu_si128: Performs an unaligned store of a u128.
//
// * _mm_sign_epi8:     Retains, negates, or zeroes each i8 lane of the first
//                      argument if the corresponding lane of the second
//                      argument is positive, negative, or zero, respectively.
// * _mm_movemask_epi8: Selects the sign bit out of each i8 lane and produces a
//                      bitmask consisting of those bits.
// * _mm_shuffle_epi8:  Selects i8s from the first argument, using the low
//                      four bits of each i8 lane in the second argument as
//                      indices.
typedef __m128i CWISS_Group;
#define CWISS_Group_kWidth ((size_t)16)
#define CWISS_Group_kShift 0

// https://github.com/abseil/abseil-cpp/issues/209
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=87853
// _mm_cmpgt_epi8 is broken under GCC with -funsigned-char
// Work around this by using the portable implementation of Group
// when using -funsigned-char under GCC.
static inline CWISS_Group CWISS_mm_cmpgt_epi8_fixed(CWISS_Group a,
		CWISS_Group b) {
	if (CWISS_IS_GCC && CHAR_MIN == 0) {  // std::is_unsigned_v<char>
		const CWISS_Group mask = _mm_set1_epi8(0x80);
		const CWISS_Group diff = _mm_subs_epi8(b, a);
		return _mm_cmpeq_epi8(_mm_and_si128(diff, mask), mask);
	}
	return _mm_cmpgt_epi8(a, b);
}

static inline CWISS_Group CWISS_Group_new(const CWISS_ControlByte* pos) {
	return _mm_loadu_si128((const CWISS_Group*)pos);
}

// Returns a bitmask representing the positions of slots that match hash.
static inline CWISS_BitMask CWISS_Group_Match(const CWISS_Group* self,
		CWISS_h2_t hash) {
	return CWISS_Group_BitMask(
			_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_set1_epi8(hash), *self)))
}

// Returns a bitmask representing the positions of empty slots.
static inline CWISS_BitMask CWISS_Group_MatchEmpty(const CWISS_Group* self) {
#if CWISS_HAVE_SSSE3
	// This only works because ctrl_t::kEmpty is -128.
	return CWISS_Group_BitMask(_mm_movemask_epi8(_mm_sign_epi8(*self, *self)));
#else
	return CWISS_Group_Match(self, CWISS_kEmpty);
#endif
}

// Returns a bitmask representing the positions of empty or deleted slots.
static inline CWISS_BitMask CWISS_Group_MatchEmptyOrDeleted(const CWISS_Group* self) {
	CWISS_Group special = _mm_set1_epi8((uint8_t)CWISS_kSentinel);
	return CWISS_Group_BitMask(_mm_movemask_epi8(CWISS_mm_cmpgt_epi8_fixed(special, *self)));
}

// Returns the number of trailing empty or deleted elements in the group.
static inline uint32_t CWISS_Group_CountLeadingEmptyOrDeleted(
		const CWISS_Group* self) {
	CWISS_Group special = _mm_set1_epi8((uint8_t)CWISS_kSentinel);
	return CWISS_TrailingZeros((uint32_t)(_mm_movemask_epi8(CWISS_mm_cmpgt_epi8_fixed(special, *self)) + 1));
}

static inline void CWISS_Group_ConvertSpecialToEmptyAndFullToDeleted(const CWISS_Group* self, CWISS_ControlByte* dst) {
	CWISS_Group msbs = _mm_set1_epi8((char)-128);
	CWISS_Group x126 = _mm_set1_epi8(126);
#if CWISS_HAVE_SSSE3
	CWISS_Group res = _mm_or_si128(_mm_shuffle_epi8(x126, *self), msbs);
#else
	CWISS_Group zero = _mm_setzero_si128();
	CWISS_Group special_mask = CWISS_mm_cmpgt_epi8_fixed(zero, *self);
	CWISS_Group res = _mm_or_si128(msbs, _mm_andnot_si128(special_mask, x126));
#endif
	_mm_storeu_si128((CWISS_Group*)dst, res);
}
#else  // CWISS_HAVE_SSE2
typedef uint64_t CWISS_Group;
#define CWISS_Group_kWidth ((size_t)8)
#define CWISS_Group_kShift 3

#if CWISS_HAVE_CLANG_BUILTIN(__builtin_bswap64)
# define bswap64 __builtin_bswap64
#else
static inline uint64_t bswap64(uint64_t v) {
	return ((v & ((uint64_t)0xff << (7 * 8))) >> (7 * 8)) |
		((v & ((uint64_t)0xff << (6 * 8))) >> (5 * 8)) |
		((v & ((uint64_t)0xff << (5 * 8))) >> (3 * 8)) |
		((v & ((uint64_t)0xff << (4 * 8))) >> (1 * 8)) |
		((v & ((uint64_t)0xff << (3 * 8))) << (1 * 8)) |
		((v & ((uint64_t)0xff << (2 * 8))) << (3 * 8)) |
		((v & ((uint64_t)0xff << (1 * 8))) << (5 * 8)) |
		((v & ((uint64_t)0xff << (0 * 8))) << (7 * 8));
}
#endif

static inline CWISS_Group CWISS_Group_new(const CWISS_ControlByte* pos) {
	CWISS_Group val;
	memcpy(&val, pos, sizeof(val));
#if CWISS_IS_BIG_ENDIAN
	val = bswap64(val);
#endif
	return val;
}

static inline CWISS_BitMask CWISS_Group_Match(const CWISS_Group* self,
		CWISS_h2_t hash) {
	// For the technique, see:
	// http://graphics.stanford.edu/~seander/bithacks.html##ValueInWord
	// (Determine if a word has a byte equal to n).
	//
	// Caveat: there are false positives but:
	// - they only occur if there is a real match
	// - they never occur on ctrl_t::kEmpty, ctrl_t::kDeleted, ctrl_t::kSentinel
	// - they will be handled gracefully by subsequent checks in code
	//
	// Example:
	//   v = 0x1716151413121110
	//   hash = 0x12
	//   retval = (v - lsbs) & ~v & msbs = 0x0000000080800000
	uint64_t msbs = 0x8080808080808080ULL;
	uint64_t lsbs = 0x0101010101010101ULL;
	uint64_t x = *self ^ (lsbs * hash);
	return CWISS_Group_BitMask((x - lsbs) & ~x & msbs);
}

static inline CWISS_BitMask CWISS_Group_MatchEmpty(const CWISS_Group* self) {
	uint64_t msbs = 0x8080808080808080ULL;
	return CWISS_Group_BitMask((*self & (~*self << 6)) & msbs);
}

static inline CWISS_BitMask CWISS_Group_MatchEmptyOrDeleted(
		const CWISS_Group* self) {
	uint64_t msbs = 0x8080808080808080ULL;
	return CWISS_Group_BitMask((*self & (~*self << 7)) & msbs);
}

static inline uint32_t CWISS_Group_CountLeadingEmptyOrDeleted(
		const CWISS_Group* self) {
	uint64_t gaps = 0x00FEFEFEFEFEFEFEULL;
	return (CWISS_TrailingZeros(((~*self & (*self >> 7)) | gaps) + 1) + 7) >> 3;
}

static inline void CWISS_Group_ConvertSpecialToEmptyAndFullToDeleted(
		const CWISS_Group* self, CWISS_ControlByte* dst) {
	uint64_t msbs = 0x8080808080808080ULL;
	uint64_t lsbs = 0x0101010101010101ULL;
	uint64_t x = *self & msbs;
	uint64_t res = (~x + (x >> 7)) & ~lsbs;
	memcpy(dst, &res, sizeof(res));
}
#endif  // CWISS_HAVE_SSE2

CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/control_byte.h /////////////////////////////////////////

/// cwisstable/internal/capacity.h /////////////////////////////////////////////
/// Capacity, load factor, and allocation size computations for a SwissTable.
///
/// A SwissTable's backing array consists of control bytes followed by slots
/// that may or may not contain objects.
///
/// The layout of the backing array, for `capacity` slots, is thus, as a
/// pseudo-struct:
/// ```
/// struct CWISS_BackingArray {
///   // Control bytes for the "real" slots.
///   CWISS_ControlByte ctrl[capacity];
///   // Always `CWISS_kSentinel`. This is used by iterators to find when to
///   // stop and serves no other purpose.
///   CWISS_ControlByte sentinel;
///   // A copy of the first `kWidth - 1` elements of `ctrl`. This is used so
///   // that if a probe sequence picks a value near the end of `ctrl`,
///   // `CWISS_Group` will have valid control bytes to look at.
///   //
///   // As an interesting special-case, such probe windows will never choose
///   // the zeroth slot as a candidate, because they will see `kSentinel`
///   // instead of the correct H2 value.
///   CWISS_ControlByte clones[kWidth - 1];
///   // Alignment padding equal to `alignof(slot_type)`.
///   char padding_;
///   // The actual slot data.
///   char slots[capacity * sizeof(slot_type)];
/// };
/// ```
///
/// The length of this array is computed by `CWISS_AllocSize()`.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// Returns he number of "cloned control bytes".
///
/// This is the number of control bytes that are present both at the beginning
/// of the control byte array and at the end, such that we can create a
/// `CWISS_Group_kWidth`-width probe window starting from any control byte.
static inline size_t CWISS_NumClonedBytes(void) {
	return CWISS_Group_kWidth - 1;
}

/// Returns whether `n` is a valid capacity (i.e., number of slots).
///
/// A valid capacity is a non-zero integer `2^m - 1`.
static inline bool CWISS_IsValidCapacity(size_t n) {
	return ((n + 1) & n) == 0 && n > 0;
}

/// Returns some per-call entropy.
///
/// Currently, the entropy is produced by XOR'ing the address of a (preferably
/// thread-local) value with a perpetually-incrementing value.
static inline size_t RandomSeed(void) {
#ifdef CWISS_THREAD_LOCAL
	static CWISS_THREAD_LOCAL size_t counter;
	size_t value = counter++;
#else
	static CWISS_ATOMIC_T(size_t) counter;
	size_t value = CWISS_ATOMIC_INC (counter);
#endif
	return value ^ ((size_t)&counter);
}

/// Mixes a randomly generated per-process seed with `hash` and `ctrl` to
/// randomize insertion order within groups.
CWISS_INLINE_NEVER static bool CWISS_ShouldInsertBackwards(
		size_t hash, const CWISS_ControlByte* ctrl) {
	// To avoid problems with weak hashes and single bit tests, we use % 13.
	// TODO(kfm,sbenza): revisit after we do unconditional mixing
	return (CWISS_H1(hash, ctrl) ^ RandomSeed()) % 13 > 6;
}

/// Applies the following mapping to every byte in the control array:
///   * kDeleted -> kEmpty
///   * kEmpty -> kEmpty
///   * _ -> kDeleted
///
/// Preconditions: `CWISS_IsValidCapacity(capacity)`,
/// `ctrl[capacity]` == `kSentinel`, `ctrl[i] != kSentinel for i < capacity`.
CWISS_INLINE_NEVER static void CWISS_ConvertDeletedToEmptyAndFullToDeleted( CWISS_ControlByte* ctrl, size_t capacity) {
	CWISS_DCHECK(ctrl[capacity] == CWISS_kSentinel, "bad ctrl value at %zu: %02x", capacity, ctrl[capacity]);
	CWISS_DCHECK(CWISS_IsValidCapacity(capacity), "invalid capacity: %zu", capacity);

	CWISS_ControlByte* pos;
	for (pos = ctrl; pos < ctrl + capacity; pos += CWISS_Group_kWidth) {
		CWISS_Group g = CWISS_Group_new(pos);
		CWISS_Group_ConvertSpecialToEmptyAndFullToDeleted(&g, pos);
	}
	// Copy the cloned ctrl bytes.
	memcpy(ctrl + capacity + 1, ctrl, CWISS_NumClonedBytes());
	ctrl[capacity] = CWISS_kSentinel;
}

/// Sets `ctrl` to `{kEmpty, ..., kEmpty, kSentinel}`, marking the entire
/// array as deleted.
static inline void CWISS_ResetCtrl(size_t capacity, CWISS_ControlByte* ctrl, const void* slots, size_t slot_size) {
	memset(ctrl, CWISS_kEmpty, capacity + 1 + CWISS_NumClonedBytes());
	ctrl[capacity] = CWISS_kSentinel;
	CWISS_PoisonMemory(slots, slot_size * capacity);
}

/// Sets `ctrl[i]` to `h`.
///
/// Unlike setting it directly, this function will perform bounds checks and
/// mirror the value to the cloned tail if necessary.
static inline void CWISS_SetCtrl(size_t i, CWISS_ControlByte h, size_t capacity, CWISS_ControlByte* ctrl, const void* slots, size_t slot_size) {
	CWISS_DCHECK(i < capacity, "CWISS_SetCtrl out-of-bounds: %zu >= %zu", i, capacity);

	const char* slot = ((const char*)slots) + i * slot_size;
	if (CWISS_IsFull(h)) {
		CWISS_UnpoisonMemory(slot, slot_size);
	} else {
		CWISS_PoisonMemory(slot, slot_size);
	}

	// This is intentionally branchless. If `i < kWidth`, it will write to the
	// cloned bytes as well as the "real" byte; otherwise, it will store `h`
	// twice.
	size_t mirrored_i = ((i - CWISS_NumClonedBytes()) & capacity) + (CWISS_NumClonedBytes() & capacity);
	ctrl[i] = h;
	ctrl[mirrored_i] = h;
}

/// Converts `n` into the next valid capacity, per `CWISS_IsValidCapacity`.
static inline size_t CWISS_NormalizeCapacity(size_t n) {
	return n ? SIZE_MAX >> CWISS_LeadingZeros(n) : 1;
}

// General notes on capacity/growth methods below:
// - We use 7/8th as maximum load factor. For 16-wide groups, that gives an
//   average of two empty slots per group.
// - For (capacity+1) >= Group::kWidth, growth is 7/8*capacity.
// - For (capacity+1) < Group::kWidth, growth == capacity. In this case, we
//   never need to probe (the whole table fits in one group) so we don't need a
//   load factor less than 1.

/// Given `capacity`, applies the load factor; i.e., it returns the maximum
/// number of values we should put into the table before a rehash.
static inline size_t CWISS_CapacityToGrowth(size_t capacity) {
	CWISS_DCHECK(CWISS_IsValidCapacity(capacity), "invalid capacity: %zu",
			capacity);
	// `capacity*7/8`
	if (CWISS_Group_kWidth == 8 && capacity == 7) {
		// x-x/8 does not work when x==7.
		return 6;
	}
	return capacity - capacity / 8;
}

/// Given `growth`, "unapplies" the load factor to find how large the capacity
/// should be to stay within the load factor.
///
/// This might not be a valid capacity and `CWISS_NormalizeCapacity()` may be
/// necessary.
static inline size_t CWISS_GrowthToLowerboundCapacity(size_t growth) {
	// `growth*8/7`
	if (CWISS_Group_kWidth == 8 && growth == 7) {
		// x+(x-1)/7 does not work when x==7.
		return 8;
	}
	return growth + (size_t)((((int64_t)growth) - 1) / 7);
}

// The allocated block consists of `capacity + 1 + NumClonedBytes()` control
// bytes followed by `capacity` slots, which must be aligned to `slot_align`.
// SlotOffset returns the offset of the slots into the allocated block.

/// Given the capacity of a table, computes the offset (from the start of the
/// backing allocation) at which the slots begin.
static inline size_t CWISS_SlotOffset(size_t capacity, size_t slot_align) {
	CWISS_DCHECK(CWISS_IsValidCapacity(capacity), "invalid capacity: %zu",
			capacity);
	const size_t num_control_bytes = capacity + 1 + CWISS_NumClonedBytes();
	return (num_control_bytes + slot_align - 1) & (~slot_align + 1);
}

/// Given the capacity of a table, computes the total size of the backing
/// array.
static inline size_t CWISS_AllocSize(size_t capacity, size_t slot_size,
		size_t slot_align) {
	return CWISS_SlotOffset(capacity, slot_align) + capacity * slot_size;
}

/// Whether a table is "small". A small table fits entirely into a probing
/// group, i.e., has a capacity equal to the size of a `CWISS_Group`.
///
/// In small mode we are able to use the whole capacity. The extra control
/// bytes give us at least one "empty" control byte to stop the iteration.
/// This is important to make 1 a valid capacity.
///
/// In small mode only the first `capacity` control bytes after the sentinel
/// are valid. The rest contain dummy ctrl_t::kEmpty values that do not
/// represent a real slot. This is important to take into account on
/// `CWISS_FindFirstNonFull()`, where we never try
/// `CWISS_ShouldInsertBackwards()` for small tables.
static inline bool CWISS_IsSmall(size_t capacity) {
	return capacity < CWISS_Group_kWidth - 1;
}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/capacity.h /////////////////////////////////////////////

/// cwisstable/internal/probe.h ////////////////////////////////////////////////
/// Table probing functions.
///
/// "Probing" refers to the process of trying to find the matching entry for a
/// given lookup by repeatedly searching for values throughout the table.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// The state for a probe sequence.
///
/// Currently, the sequence is a triangular progression of the form
/// ```
/// p(i) := kWidth/2 * (i^2 - i) + hash (mod mask + 1)
/// ```
///
/// The use of `kWidth` ensures that each probe step does not overlap groups;
/// the sequence effectively outputs the addresses of *groups* (although not
/// necessarily aligned to any boundary). The `CWISS_Group` machinery allows us
/// to check an entire group with minimal branching.
///
/// Wrapping around at `mask + 1` is important, but not for the obvious reason.
/// As described in capacity.h, the first few entries of the control byte array
/// is mirrored at the end of the array, which `CWISS_Group` will find and use
/// for selecting candidates. However, when those candidates' slots are
/// actually inspected, there are no corresponding slots for the cloned bytes,
/// so we need to make sure we've treated those offsets as "wrapping around".
typedef struct {
	size_t mask_;
	size_t offset_;
	size_t index_;
} CWISS_ProbeSeq;

/// Creates a new probe sequence using `hash` as the initial value of the
/// sequence and `mask` (usually the capacity of the table) as the mask to
/// apply to each value in the progression.
static inline CWISS_ProbeSeq CWISS_ProbeSeq_new(size_t hash, size_t mask) {
	return (CWISS_ProbeSeq) {
		.mask_ = mask,
			.offset_ = hash & mask,
	};
}

/// Returns the slot `i` indices ahead of `self` within the bounds expressed by
/// `mask`.
static inline size_t CWISS_ProbeSeq_offset(const CWISS_ProbeSeq* self,
		size_t i) {
	return (self->offset_ + i) & self->mask_;
}

/// Advances the sequence; the value can be obtained by calling
/// `CWISS_ProbeSeq_offset()` or inspecting `offset_`.
static inline void CWISS_ProbeSeq_next(CWISS_ProbeSeq* self) {
	self->index_ += CWISS_Group_kWidth;
	self->offset_ += self->index_;
	self->offset_ &= self->mask_;
}

/// Begins a probing operation on `ctrl`, using `hash`.
static inline CWISS_ProbeSeq CWISS_ProbeSeq_Start(const CWISS_ControlByte* ctrl,
		size_t hash,
		size_t capacity) {
	return CWISS_ProbeSeq_new(CWISS_H1(hash, ctrl), capacity);
}

// The return value of `CWISS_FindFirstNonFull()`.
typedef struct {
	size_t offset;
	size_t probe_length;
} CWISS_FindInfo;

/// Probes an array of control bits using a probe sequence derived from `hash`,
/// and returns the offset corresponding to the first deleted or empty slot.
///
/// Behavior when the entire table is full is undefined.
///
/// NOTE: this function must work with tables having both empty and deleted
/// slots in the same group. Such tables appear during
/// `CWISS_RawTable_DropDeletesWithoutResize()`.
static inline CWISS_FindInfo CWISS_FindFirstNonFull(
		const CWISS_ControlByte* ctrl, size_t hash, size_t capacity) {
	CWISS_ProbeSeq seq = CWISS_ProbeSeq_Start(ctrl, hash, capacity);
	while (true) {
		CWISS_Group g = CWISS_Group_new(ctrl + seq.offset_);
		CWISS_BitMask mask = CWISS_Group_MatchEmptyOrDeleted(&g);
		if (mask.mask) {
#ifndef NDEBUG
			// We want to add entropy even when ASLR is not enabled.
			// In debug build we will randomly insert in either the front or back of
			// the group.
			// TODO(kfm,sbenza): revisit after we do unconditional mixing
			if (!CWISS_IsSmall(capacity) && CWISS_ShouldInsertBackwards(hash, ctrl)) {
				return (CWISS_FindInfo) {
					CWISS_ProbeSeq_offset(&seq, CWISS_BitMask_HighestBitSet(&mask)),
						seq.index_
				};
			}
#endif
			return (CWISS_FindInfo) {
				CWISS_ProbeSeq_offset(&seq, CWISS_BitMask_TrailingZeros(&mask)),
					seq.index_
			};
		}
		CWISS_ProbeSeq_next(&seq);
		CWISS_DCHECK(seq.index_ <= capacity, "full table!");
	}
}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/probe.h ////////////////////////////////////////////////

/// cwisstable/internal/absl_hash.h ////////////////////////////////////////////
/// Implementation details of AbslHash.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

static inline uint64_t CWISS_AbslHash_LowLevelMix(uint64_t v0, uint64_t v1) {
#if USE_128_MIX
	// The default bit-mixer uses 64x64->128-bit multiplication.
	CWISS_U128 p = CWISS_Mul128(v0, v1);
	return p.hi ^ p.lo;
#else
	// The default bit-mixer above would perform poorly on some ARM microarchs,
	// where calculating a 128-bit product requires a sequence of two
	// instructions with a high combined latency and poor throughput.
	// Instead, we mix bits using only 64-bit arithmetic, which is faster.
	uint64_t p = v0 ^ CWISS_RotateLeft(v1, 40);
	p *= v1 ^ CWISS_RotateLeft(v0, 39);
	return p ^ (p >> 11);
#endif
}

CWISS_INLINE_NEVER
static uint64_t CWISS_AbslHash_LowLevelHash(const void* data, size_t len,
		uint64_t seed,
		const uint64_t salt[5]) {
	const char* ptr = (const char*)data;
	uint64_t starting_length = (uint64_t)len;
	uint64_t current_state = seed ^ salt[0];

	if (len > 64) {
		// If we have more than 64 bytes, we're going to handle chunks of 64
		// bytes at a time. We're going to build up two separate hash states
		// which we will then hash together.
		uint64_t duplicated_state = current_state;

		do {
			uint64_t chunk[8];
			memcpy(chunk, ptr, sizeof(chunk));

			uint64_t cs0 = CWISS_AbslHash_LowLevelMix(chunk[0] ^ salt[1],
					chunk[1] ^ current_state);
			uint64_t cs1 = CWISS_AbslHash_LowLevelMix(chunk[2] ^ salt[2],
					chunk[3] ^ current_state);
			current_state = (cs0 ^ cs1);

			uint64_t ds0 = CWISS_AbslHash_LowLevelMix(chunk[4] ^ salt[3],
					chunk[5] ^ duplicated_state);
			uint64_t ds1 = CWISS_AbslHash_LowLevelMix(chunk[6] ^ salt[4],
					chunk[7] ^ duplicated_state);
			duplicated_state = (ds0 ^ ds1);

			ptr += 64;
			len -= 64;
		} while (len > 64);

		current_state = current_state ^ duplicated_state;
	}

	// We now have a data `ptr` with at most 64 bytes and the current state
	// of the hashing state machine stored in current_state.
	while (len > 16) {
		uint64_t a = CWISS_Load64(ptr);
		uint64_t b = CWISS_Load64(ptr + 8);

		current_state = CWISS_AbslHash_LowLevelMix(a ^ salt[1], b ^ current_state);

		ptr += 16;
		len -= 16;
	}

	// We now have a data `ptr` with at most 16 bytes.
	uint64_t a = 0;
	uint64_t b = 0;
	if (len > 8) {
		// When we have at least 9 and at most 16 bytes, set A to the first 64
		// bits of the input and B to the last 64 bits of the input. Yes, they will
		// overlap in the middle if we are working with less than the full 16
		// bytes.
		a = CWISS_Load64(ptr);
		b = CWISS_Load64(ptr + len - 8);
	}
	else if (len > 3) {
		// If we have at least 4 and at most 8 bytes, set A to the first 32
		// bits and B to the last 32 bits.
		a = CWISS_Load32(ptr);
		b = CWISS_Load32(ptr + len - 4);
	}
	else if (len > 0) {
		// If we have at least 1 and at most 3 bytes, read all of the provided
		// bits into A, with some adjustments.
		a = CWISS_Load1To3(ptr, len);
	}

	uint64_t w = CWISS_AbslHash_LowLevelMix(a ^ salt[1], b ^ current_state);
	uint64_t z = salt[1] ^ starting_length;
	return CWISS_AbslHash_LowLevelMix(w, z);
}

// A non-deterministic seed.
//
// The current purpose of this seed is to generate non-deterministic results
// and prevent having users depend on the particular hash values.
// It is not meant as a security feature right now, but it leaves the door
// open to upgrade it to a true per-process random seed. A true random seed
// costs more and we don't need to pay for that right now.
//
// On platforms with ASLR, we take advantage of it to make a per-process
// random value.
// See https://en.wikipedia.org/wiki/Address_space_layout_randomization
//
// On other platforms this is still going to be non-deterministic but most
// probably per-build and not per-process.
static const void* const CWISS_AbslHash_kSeed = &CWISS_AbslHash_kSeed;

// The salt array used by LowLevelHash. This array is NOT the mechanism used to
// make absl::Hash non-deterministic between program invocations.  See `Seed()`
// for that mechanism.
//
// Any random values are fine. These values are just digits from the decimal
// part of pi.
// https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number
static const uint64_t CWISS_AbslHash_kHashSalt[5] = {
	0x243F6A8885A308D3ULL, 0x13198A2E03707344, 0xA4093822299F31D0ULL,
	0x082EFA98EC4E6C89ULL, 0x452821E638D01377ULL,
};

#define CWISS_AbslHash_kPiecewiseChunkSize ((size_t)1024)

typedef uint64_t CWISS_AbslHash_State_;
#define CWISS_AbslHash_kInit_ ((CWISS_AbslHash_State_)(uintptr_t)CWISS_AbslHash_kSeed)

static inline void CWISS_AbslHash_Mix(CWISS_AbslHash_State_* state, uint64_t v) {
	const uint64_t kMul = (sizeof (size_t) == 4) ? 0xcc9e2d51ULL : 0x9ddfea08eb382d69ULL;
	*state = CWISS_AbslHash_LowLevelMix (*state + v, kMul);
}

CWISS_INLINE_NEVER
static uint64_t CWISS_AbslHash_Hash64(const void* val, size_t len) {
	return CWISS_AbslHash_LowLevelHash (val, len, CWISS_AbslHash_kInit_, CWISS_AbslHash_kHashSalt);
}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/absl_hash.h ////////////////////////////////////////////

/// cwisstable/hash.h //////////////////////////////////////////////////////////
/// Hash functions.
///
/// This file provides some hash functions to use with cwisstable types.
///
/// Every hash function defines four symbols:
///   - `CWISS_<Hash>_State`, the state of the hash function.
///   - `CWISS_<Hash>_kInit`, the initial value of the hash state.
///   - `void CWISS_<Hash>_Write(State*, const void*, size_t)`, write some more
///     data into the hash state.
///   - `size_t CWISS_<Hash>_Finish(State)`, digest the state into a final hash
///     value.
///
/// Currently available are two hashes: `FxHash`, which is small and fast, and
/// `AbslHash`, the hash function used by Abseil.
///
/// `AbslHash` is the default hash function.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

typedef size_t CWISS_FxHash_State;
#define CWISS_FxHash_kInit ((CWISS_FxHash_State)0)
static inline void CWISS_FxHash_Write(CWISS_FxHash_State* state,
		const void* val, size_t len) {
	const size_t kSeed = (size_t)(0x517cc1b727220a95ULL);
	const uint32_t kRotate = 5;

	const char* p = (const char*)val;
	CWISS_FxHash_State state_ = *state;
	while (len > 0) {
		size_t word = 0;
		size_t to_read = len >= sizeof(state_) ? sizeof(state_) : len;
		memcpy(&word, p, to_read);

		state_ = CWISS_RotateLeft(state_, kRotate);
		state_ ^= word;
		state_ *= kSeed;

		len -= to_read;
		p += to_read;
	}
	*state = state_;
}
static inline size_t CWISS_FxHash_Finish(CWISS_FxHash_State state) {
	return state;
}

typedef CWISS_AbslHash_State_ CWISS_AbslHash_State;
#define CWISS_AbslHash_kInit CWISS_AbslHash_kInit_
static inline void CWISS_AbslHash_Write(CWISS_AbslHash_State* state,
		const void* val, size_t len) {
	const char* val8 = (const char*)val;
	if (CWISS_LIKELY(len < CWISS_AbslHash_kPiecewiseChunkSize)) {
		goto CWISS_AbslHash_Write_small;
	}

	while (len >= CWISS_AbslHash_kPiecewiseChunkSize) {
		CWISS_AbslHash_Mix(
				state, CWISS_AbslHash_Hash64(val8, CWISS_AbslHash_kPiecewiseChunkSize));
		len -= CWISS_AbslHash_kPiecewiseChunkSize;
		val8 += CWISS_AbslHash_kPiecewiseChunkSize;
	}

CWISS_AbslHash_Write_small:;
			   uint64_t v;
			   if (len > 16) {
				   v = CWISS_AbslHash_Hash64(val8, len);
			   }
			   else if (len > 8) {
				   CWISS_U128 p = CWISS_Load9To16(val8, len);
				   CWISS_AbslHash_Mix(state, p.lo);
				   v = p.hi;
			   }
			   else if (len >= 4) {
				   v = CWISS_Load4To8(val8, len);
			   }
			   else if (len > 0) {
				   v = CWISS_Load1To3(val8, len);
			   }
			   else {
				   // Empty ranges have no effect.
				   return;
			   }

			   CWISS_AbslHash_Mix(state, v);
}
static inline size_t CWISS_AbslHash_Finish(CWISS_AbslHash_State state) {
	return state;
}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/hash.h //////////////////////////////////////////////////////////

/// cwisstable/policy.h ////////////////////////////////////////////////////////
/// Hash table policies.
///
/// Table policies are `cwisstable`'s generic code mechanism. All code in
/// `cwisstable`'s internals is completely agnostic to:
/// - The layout of the elements.
/// - The storage strategy for the elements (inline, indirect in the heap).
/// - Hashing, comparison, and allocation.
///
/// This information is provided to `cwisstable`'s internals by way of a
/// *policy*: a vtable describing how to move elements around, hash them,
/// compare them, allocate storage for them, and so on and on. This design is
/// inspired by Abseil's equivalent, which is a template parameter used for
/// sharing code between all the SwissTable-backed containers.
///
/// Unlike Abseil, policies are part of `cwisstable`'s public interface. Due to
/// C's lack of any mechanism for detecting the gross properties of types,
/// types with unwritten invariants, such as C strings (NUL-terminated byte
/// arrays), users must be able to carefully describe to `cwisstable` how to
/// correctly do things to their type. DESIGN.md goes into detailed rationale
/// for this polymorphism strategy.
///
/// # Defining a Policy
///
/// Policies are defined as read-only globals and passed around by pointer to
/// different `cwisstable` functions; macros are provided for doing this, since
/// most of these functions will not vary significantly from one type to
/// another. There are four of them:
///
/// - `CWISS_DECLARE_FLAT_SET_POLICY(kPolicy, Type, ...)`
/// - `CWISS_DECLARE_FLAT_MAP_POLICY(kPolicy, Key, Value, ...)`
/// - `CWISS_DECLARE_NODE_SET_POLICY(kPolicy, Type, ...)`
/// - `CWISS_DECLARE_NODE_MAP_POLICY(kPolicy, Key, Value, ...)`
///
/// These correspond to the four SwissTable types in Abseil: two map types and
/// two set types; "flat" means that elements are stored inline in the backing
/// array, whereas "node" means that the element is stored in its own heap
/// allocation, making it stable across rehashings (which SwissTable does more
/// or less whenever it feels like it).
///
/// Each macro expands to a read-only global variable definition (with the name
/// `kPolicy`, i.e, the first variable) dedicated for the specified type(s).
/// The arguments that follow are overrides for the default values of each field
/// in the policy; all but the size and alignment fields of `CWISS_ObjectPolicy`
/// may be overridden. To override the field `kPolicy.foo.bar`, pass
/// `(foo_bar, value)` to the macro. If multiple such pairs are passed in, the
/// first one found wins. `examples/stringmap.c` provides an example of how to
/// use this functionality.
///
/// For "common" uses, where the key and value are plain-old-data, `declare.h`
/// has dedicated macros, and fussing with policies directly is unnecessary.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// A policy describing the basic laying properties of a type.
///
/// This type describes how to move values of a particular type around.
typedef struct {
	/// The layout of the stored object.
	size_t size, align;

	/// Performs a deep copy of `src` onto a fresh location `dst`.
	void (*copy)(void* dst, const void* src);

	/// Destroys an object.
	///
	/// This member may, as an optimization, be null. This will cause it to
	/// behave as a no-op, and may be more efficient than making this an empty
	/// function.
	void (*dtor)(void* val);
} CWISS_ObjectPolicy;

/// A policy describing the hashing properties of a type.
///
/// This type describes the necessary information for putting a value into a
/// hash table.
///
/// A *heterogenous* key policy is one whose equality function expects different
/// argument types, which can be used for so-called heterogenous lookup: finding
/// an element of a table by comparing it to a somewhat different type. If the
/// table element is, for example, a `std::string`[1]-like type, it could still
/// be found via a non-owning version like a `std::string_view`[2]. This is
/// important for making efficient use of a SwissTable.
///
/// [1]: For non C++ programmers: a growable string type implemented as a
///      `struct { char* ptr; size_t size, capacity; }`.
/// [2]: Similarly, a `std::string_view` is a pointer-length pair to a string
///      *somewhere*; unlike a C-style string, it might be a substring of a
///      larger allocation elsewhere.
typedef struct {
	/// Computes the hash of a value.
	///
	/// This function must be such that if two elements compare equal, they must
	/// have the same hash (but not vice-versa).
	///
	/// If this policy is heterogenous, this function must be defined so that
	/// given the original key policy of the table's element type, if
	/// `hetero->eq(a, b)` holds, then `hetero->hash(a) == original->hash(b)`.
	/// In other words, the obvious condition for a hash table to work correctly
	/// with this policy.
	size_t(*hash)(const void* val);

	/// Compares two values for equality.
	///
	/// This function is actually not symmetric: the first argument will always be
	/// the value being searched for, and the second will be a pointer to the
	/// candidate entry. In particular, this means they can be different types:
	/// in C++ parlance, `needle` could be a `std::string_view`, while `candidate`
	/// could be a `std::string`.
	bool (*eq)(const void* needle, const void* candidate);
} CWISS_KeyPolicy;

/// A policy for allocation.
///
/// This type provides access to a custom allocator.
typedef struct {
	/// Allocates memory.
	///
	/// This function must never fail and never return null, unlike `malloc`. This
	/// function does not need to tolerate zero sized allocations.
	void* (*alloc)(size_t size, size_t align);

	/// Deallocates memory allocated by `alloc`.
	///
	/// This function is passed the same size/alignment as was passed to `alloc`,
	/// allowing for sized-delete optimizations.
	void (*free)(void* array, size_t size, size_t align);
} CWISS_AllocPolicy;

/// A policy for allocating space for slots.
///
/// This allows us to distinguish between inline storage (more cache-friendly)
/// and outline (pointer-stable).
typedef struct {
	/// The layout of a slot value.
	///
	/// Usually, this will be the same as for the object type, *or* the layout
	/// of a pointer (for outline storage).
	size_t size, align;

	/// Initializes a new slot at the given location.
	///
	/// This function does not initialize the value *in* the slot; it simply sets
	/// up the slot so that a value can be `memcpy`'d or otherwise emplaced into
	/// the slot.
	void (*init)(void* slot);

	/// Destroys a slot, including the destruction of the value it contains.
	///
	/// This function may, as an optimization, be null. This will cause it to
	/// behave as a no-op.
	void (*del)(void* slot);

	/// Transfers a slot.
	///
	/// `dst` must be uninitialized; `src` must be initialized. After this
	/// function, their roles will be switched: `dst` will be initialized and
	/// contain the value from `src`; `src` will be initialized.
	///
	/// This function need not actually copy the underlying value.
	void (*transfer)(void* dst, void* src);

	/// Extracts a pointer to the value inside the a slot.
	///
	/// This function does not need to tolerate nulls.
	void* (*get)(void* slot);
} CWISS_SlotPolicy;

/// A hash table policy.
///
/// See the header documentation for more information.
typedef struct {
	const CWISS_ObjectPolicy* obj;
	const CWISS_KeyPolicy* key;
	const CWISS_AllocPolicy* alloc;
	const CWISS_SlotPolicy* slot;
} CWISS_Policy;

/// Declares a hash set policy with inline storage for the given type.
///
/// See the header documentation for more information.
#define CWISS_DECLARE_FLAT_SET_POLICY(kPolicy_, Type_, obj_copy, obj_dtor, key_hash, key_eq) \
	CWISS_DECLARE_FLAT_POLICY_(kPolicy_, Type_, Type_, obj_copy, obj_dtor, key_hash, key_eq)

/// Declares a hash set policy with pointer-stable storage for the given type.
///
/// See the header documentation for more information.
#define CWISS_DECLARE_NODE_SET_POLICY(kPolicy_, Type_, obj_copy, obj_dtor, key_hash, key_eq)          \
	CWISS_DECLARE_NODE_POLICY_(kPolicy_, Type_, Type_, obj_copy, obj_dtor, key_hash, key_eq)

/// Declares a hash map policy with pointer-stable storage for the given key and
/// value types.
///
/// See the header documentation for more information.
#define CWISS_DECLARE_NODE_MAP_POLICY(kPolicy_, K_, V_, obj_copy, obj_dtor, key_hash, key_eq)                 \
	typedef struct kPolicy_##_entry_t {                                           \
		K_ k;                                                                    \
		V_ v;                                                                    \
	} kPolicy_##_Entry;                                                        \
	CWISS_DECLARE_NODE_POLICY_(kPolicy_, kPolicy_##_Entry, K_, obj_copy, obj_dtor, key_hash, key_eq)

// ---- PUBLIC API ENDS HERE! ----

/// Declares a hash map policy with inline storage for the given key and value
/// types.
///
/// See the header documentation for more information.
#define CWISS_DECLARE_FLAT_MAP_POLICY(kPolicy_, K_, V_, obj_copy, obj_dtor, key_hash, key_eq) \
	typedef struct kPolicy_##_entry_t {                                           \
		K_ k;                                                    \
		V_ v;                                                    \
	} kPolicy_##_Entry;                                        \
	CWISS_DECLARE_FLAT_POLICY_(kPolicy_, kPolicy_##_Entry, K_, obj_copy, obj_dtor, key_hash, key_eq)

#define CWISS_DECLARE_FLAT_POLICY_(kPolicy_, Type_, Key_, obj_copy, obj_dtor, key_hash, key_eq)      \
	CWISS_BEGIN                                                            \
	static inline void kPolicy_##_DefaultSlotInit(void* slot) {}                  \
	static inline void kPolicy_##_DefaultSlotTransfer(void* dst, void* src) {     \
		memcpy(dst, src, sizeof(Type_));                                     \
	}                                                                      \
	static inline void* kPolicy_##_DefaultSlotGet(void* slot) { return slot; }    \
	static inline void kPolicy_##_DefaultSlotDtor(void* slot){                   \
		obj_dtor (slot); \
	}                                                                      \
	\
	static const CWISS_ObjectPolicy kPolicy_##_ObjectPolicy = {                   \
		sizeof(Type_),                                                     \
		alignof(Type_),                                                    \
		obj_copy,     \
		obj_dtor                       \
	};                                                                     \
	static const CWISS_KeyPolicy kPolicy_##_KeyPolicy = {                         \
		key_hash, key_eq, \
	};                                                                     \
	static const CWISS_AllocPolicy kPolicy_##_AllocPolicy = {                     \
		CWISS_DefaultMalloc, \
		CWISS_DefaultFree, \
	};                                                                     \
	static const CWISS_SlotPolicy kPolicy_##_SlotPolicy = {                       \
		sizeof(Type_), \
		sizeof(Type_), \
		kPolicy_##_DefaultSlotInit, \
		kPolicy_##_DefaultSlotDtor, \
		kPolicy_##_DefaultSlotTransfer, \
		kPolicy_##_DefaultSlotGet,                                  \
	};                                                                     \
	CWISS_END                                                              \
	static const CWISS_Policy kPolicy_ = {                                   \
		&kPolicy_##_ObjectPolicy,                                          \
		&kPolicy_##_KeyPolicy,                                             \
		&kPolicy_##_AllocPolicy,                                           \
		&kPolicy_##_SlotPolicy,                                            \
	}

static inline void* CWISS_DefaultMalloc(size_t size, size_t align) {
	void* p = malloc(size);  // TODO: Check alignment.
	CWISS_CHECK(p != NULL, "malloc() returned null");
	return p;
}
static inline void CWISS_DefaultFree(void* array, size_t size, size_t align) {
	free(array);
}

#define CWISS_DECLARE_NODE_POLICY_(kPolicy_, Type_, Key_, obj_copy, obj_dtor, key_hash, key_eq)      \
	CWISS_BEGIN                                                                  \
	static inline void kPolicy_##_NodeSlotInit(void* slot) {                     \
		void* node = CWISS_DefaultMalloc(sizeof(Type_), alignof(Type_));     \
		memcpy(slot, &node, sizeof(node));                                         \
	}                                                                            \
	static inline void kPolicy_##_NodeSlotDtor(void* slot) {                     \
		obj_dtor(*(void**)slot);                                             \
		CWISS_DefaultFree(*(void**)slot, sizeof(Type_), alignof(Type_));     \
	}                                                                            \
	static inline void kPolicy_##_NodeSlotTransfer(void* dst, void* src) {       \
		memcpy(dst, src, sizeof(void*));                                           \
	}                                                                            \
	static inline void* kPolicy_##_NodeSlotGet(void* slot) {                     \
		return *((void**)slot);                                                    \
	}                                                                            \
	static const CWISS_ObjectPolicy kPolicy_##_ObjectPolicy = {                   \
		sizeof(Type_),                                                     \
		alignof(Type_),                                                    \
		obj_copy,     \
		obj_dtor                       \
	};                                                                     \
	static const CWISS_KeyPolicy kPolicy_##_KeyPolicy = {                         \
		key_hash, key_eq, \
	};                                                                     \
	static const CWISS_AllocPolicy kPolicy_##_AllocPolicy = {                     \
		CWISS_DefaultMalloc, \
		CWISS_DefaultFree, \
	};                                                                     \
	static const CWISS_SlotPolicy kPolicy_##_SlotPolicy = {                       \
		sizeof(void*), \
		alignof(void*), \
		kPolicy_##_NodeSlotInit, \
		kPolicy_##_NodeSlotDtor, \
		kPolicy_##_NodeSlotTransfer, \
		kPolicy_##_NodeSlotGet,                                  \
	};                                                                     \
	CWISS_END                                                              \
	static const CWISS_Policy kPolicy_ = {                                   \
		&kPolicy_##_ObjectPolicy,                                          \
		&kPolicy_##_KeyPolicy,                                             \
		&kPolicy_##_AllocPolicy,                                           \
		&kPolicy_##_SlotPolicy,                                            \
	}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/policy.h ////////////////////////////////////////////////////////

/// cwisstable/internal/raw_table.h ////////////////////////////////////////////
/// The SwissTable implementation.
///
/// `CWISS_RawTable` is the core data structure that all SwissTables wrap.
///
/// All functions in this header take a `const CWISS_Policy*`, which describes
/// how to manipulate the elements in a table. The same pointer (i.e., same
/// address and provenance) passed to the function that created the
/// `CWISS_RawTable` MUST be passed to all subsequent function calls, and it
/// must not be mutated at any point between those calls. Failure to adhere to
/// these requirements is UB.
///
/// It is STRONGLY recommended that this pointer point to a const global.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// A SwissTable.
///
/// This is absl::container_internal::raw_hash_set in Abseil.
typedef struct {
	/// The control bytes (and, also, a pointer to the base of the backing array).
	///
	/// This contains `capacity_ + 1 + CWISS_NumClonedBytes()` entries.
	CWISS_ControlByte* ctrl_;
	/// The beginning of the slots, located at `CWISS_SlotOffset()` bytes after
	/// `ctrl_`. May be null for empty tables.
	char* slots_;
	/// The number of filled slots.
	size_t size_;
	/// The total number of available slots.
	size_t capacity_;
	/// The number of slots we can still fill before a rehash. See
	/// `CWISS_CapacityToGrowth()`.
	size_t growth_left_;
} CWISS_RawTable;


/// An iterator into a SwissTable.
///
/// Unlike a C++ iterator, there is no "end" to compare to. Instead,
/// `CWISS_RawIter_get()` will yield a null pointer once the iterator is
/// exhausted.
///
/// Invariants:
/// - `ctrl_` and `slot_` are always in sync (i.e., the pointed to control byte
///   corresponds to the pointed to slot), or both are null. `set_` may be null
///   in the latter case.
/// - `ctrl_` always points to a full slot.
typedef struct {
	CWISS_RawTable* set_;
	CWISS_ControlByte* ctrl_;
	char* slot_;
} CWISS_RawIter;

/// Fixes up `ctrl_` to point to a full by advancing it and `slot_` until they
/// reach one.
///
/// If a sentinel is reached, we null both of them out instead.
static inline void CWISS_RawIter_SkipEmptyOrDeleted(const CWISS_Policy* policy,
		CWISS_RawIter* self) {
	while (CWISS_IsEmptyOrDeleted(*self->ctrl_)) {
		CWISS_Group g = CWISS_Group_new(self->ctrl_);
		uint32_t shift = CWISS_Group_CountLeadingEmptyOrDeleted(&g);
		self->ctrl_ += shift;
		self->slot_ += shift * policy->slot->size;
	}

	// Not sure why this is a branch rather than a cmov; Abseil uses a branch.
	if (CWISS_UNLIKELY(*self->ctrl_ == CWISS_kSentinel)) {
		self->ctrl_ = NULL;
		self->slot_ = NULL;
	}
}

/// Creates a valid iterator starting at the `index`th slot.
static inline CWISS_RawIter CWISS_RawTable_iter_at(const CWISS_Policy* policy,
		CWISS_RawTable* self,
		size_t index) {
	CWISS_RawIter iter = {
		self,
		self->ctrl_ + index,
		self->slots_ ? self->slots_ + index * policy->slot->size : NULL,
	};
	CWISS_RawIter_SkipEmptyOrDeleted(policy, &iter);
	CWISS_AssertIsValid(iter.ctrl_);
	return iter;
}

/// Creates an iterator for `self`.
static inline CWISS_RawIter CWISS_RawTable_iter(const CWISS_Policy* policy,
		CWISS_RawTable* self) {
	return CWISS_RawTable_iter_at(policy, self, 0);
}

/// Creates a valid iterator starting at the `index`th slot, accepting a `const`
/// pointer instead.
static inline CWISS_RawIter CWISS_RawTable_citer_at(const CWISS_Policy* policy,
		const CWISS_RawTable* self,
		size_t index) {
	return CWISS_RawTable_iter_at(policy, (CWISS_RawTable*)self, index);
}

/// Creates an iterator for `self`, accepting a `const` pointer instead.
static inline CWISS_RawIter CWISS_RawTable_citer(const CWISS_Policy* policy,
		const CWISS_RawTable* self) {
	return CWISS_RawTable_iter(policy, (CWISS_RawTable*)self);
}

/// Returns a pointer into the currently pointed-to slot (*not* to the slot
/// itself, but rather its contents).
///
/// Returns null if the iterator has been exhausted.
static inline void* CWISS_RawIter_get(const CWISS_Policy* policy,
		const CWISS_RawIter* self) {
	CWISS_AssertIsValid(self->ctrl_);
	if (self->slot_ == NULL) {
		return NULL;
	}

	return policy->slot->get(self->slot_);
}

/// Advances the iterator and returns the result of `CWISS_RawIter_get()`.
///
/// Calling on an empty iterator is UB.
static inline void* CWISS_RawIter_next(const CWISS_Policy* policy,
		CWISS_RawIter* self) {
	CWISS_AssertIsFull(self->ctrl_);
	self->ctrl_++;
	self->slot_ += policy->slot->size;

	CWISS_RawIter_SkipEmptyOrDeleted(policy, self);
	return CWISS_RawIter_get(policy, self);
}

/// Erases, but does not destroy, the value pointed to by `it`.
static inline void CWISS_RawTable_EraseMetaOnly(const CWISS_Policy* policy,
		CWISS_RawIter it) {
	CWISS_DCHECK(CWISS_IsFull(*it.ctrl_), "erasing a dangling iterator");
	--it.set_->size_;
	const size_t index = (size_t)(it.ctrl_ - it.set_->ctrl_);
	const size_t index_before = (index - CWISS_Group_kWidth) & it.set_->capacity_;
	CWISS_Group g_after = CWISS_Group_new(it.ctrl_);
	CWISS_BitMask empty_after = CWISS_Group_MatchEmpty(&g_after);
	CWISS_Group g_before = CWISS_Group_new(it.set_->ctrl_ + index_before);
	CWISS_BitMask empty_before = CWISS_Group_MatchEmpty(&g_before);

	// We count how many consecutive non empties we have to the right and to the
	// left of `it`. If the sum is >= kWidth then there is at least one probe
	// window that might have seen a full group.
	bool was_never_full =
		empty_before.mask && empty_after.mask &&
		(size_t)(CWISS_BitMask_TrailingZeros(&empty_after) +
				CWISS_BitMask_LeadingZeros(&empty_before)) < CWISS_Group_kWidth;

	CWISS_SetCtrl(index, was_never_full ? CWISS_kEmpty : CWISS_kDeleted,
			it.set_->capacity_, it.set_->ctrl_, it.set_->slots_,
			policy->slot->size);
	it.set_->growth_left_ += was_never_full;
	// infoz().RecordErase();
}

/// Computes a lower bound for the expected available growth and applies it to
/// `self_`.
static inline void CWISS_RawTable_ResetGrowthLeft(const CWISS_Policy* policy,
		CWISS_RawTable* self) {
	self->growth_left_ = CWISS_CapacityToGrowth(self->capacity_) - self->size_;
}

/// Allocates a backing array for `self` and initializes its control bits. This
/// reads `capacity_` and updates all other fields based on the result of the
/// allocation.
///
/// This does not free the currently held array; `capacity_` must be nonzero.
static inline void CWISS_RawTable_InitializeSlots(const CWISS_Policy* policy,
		CWISS_RawTable* self) {
	CWISS_DCHECK(self->capacity_, "capacity should be nonzero");
	// Folks with custom allocators often make unwarranted assumptions about the
	// behavior of their classes vis-a-vis trivial destructability and what
	// calls they will or wont make.  Avoid sampling for people with custom
	// allocators to get us out of this mess.  This is not a hard guarantee but
	// a workaround while we plan the exact guarantee we want to provide.
	//
	// People are often sloppy with the exact type of their allocator (sometimes
	// it has an extra const or is missing the pair, but rebinds made it work
	// anyway).  To avoid the ambiguity, we work off SlotAlloc which we have
	// bound more carefully.
	//
	// NOTE(mcyoung): Not relevant in C but kept in case we decide to do custom
	// alloc.
	/*if (std::is_same<SlotAlloc, std::allocator<slot_type>>::value &&
	  slots_ == nullptr) {
	  infoz() = Sample(sizeof(slot_type));
	  }*/

	char* mem =
		(char*)  // Cast for C++.
		policy->alloc->alloc(CWISS_AllocSize(self->capacity_, policy->slot->size,
					policy->slot->align),
				policy->slot->align);

	self->ctrl_ = (CWISS_ControlByte*)mem;
	self->slots_ = mem + CWISS_SlotOffset(self->capacity_, policy->slot->align);
	CWISS_ResetCtrl(self->capacity_, self->ctrl_, self->slots_,
			policy->slot->size);
	CWISS_RawTable_ResetGrowthLeft(policy, self);

	// infoz().RecordStorageChanged(size_, capacity_);
}

/// Destroys all slots in the backing array, frees the backing array, and clears
/// all top-level book-keeping data.
static inline void CWISS_RawTable_DestroySlots(const CWISS_Policy* policy,
		CWISS_RawTable* self) {
	if (!self->capacity_) return;

	if (policy->slot->del != NULL) {
		size_t i;
		for (i = 0; i != self->capacity_; i++) {
			if (CWISS_IsFull(self->ctrl_[i])) {
				policy->slot->del(self->slots_ + i * policy->slot->size);
			}
		}
	}

	policy->alloc->free(
			self->ctrl_,
			CWISS_AllocSize(self->capacity_, policy->slot->size, policy->slot->align),
			policy->slot->align);
	self->ctrl_ = CWISS_EmptyGroup();
	self->slots_ = NULL;
	self->size_ = 0;
	self->capacity_ = 0;
	self->growth_left_ = 0;
}

/// Grows the table to the given capacity, triggering a rehash.
static inline void CWISS_RawTable_Resize(const CWISS_Policy* policy,
		CWISS_RawTable* self,
		size_t new_capacity) {
	CWISS_DCHECK(CWISS_IsValidCapacity(new_capacity), "invalid capacity: %zu",
			new_capacity);

	CWISS_ControlByte* old_ctrl = self->ctrl_;
	char* old_slots = self->slots_;
	const size_t old_capacity = self->capacity_;
	self->capacity_ = new_capacity;
	CWISS_RawTable_InitializeSlots(policy, self);

	size_t i;
	for (i = 0; i != old_capacity; i++) {
		if (CWISS_IsFull(old_ctrl[i])) {
			size_t hash = policy->key->hash(
					policy->slot->get(old_slots + i * policy->slot->size));
			CWISS_FindInfo target =
				CWISS_FindFirstNonFull(self->ctrl_, hash, self->capacity_);
			size_t new_i = target.offset;
			CWISS_SetCtrl(new_i, CWISS_H2(hash), self->capacity_, self->ctrl_,
					self->slots_, policy->slot->size);
			policy->slot->transfer(self->slots_ + new_i * policy->slot->size,
					old_slots + i * policy->slot->size);
		}
	}
	if (old_capacity) {
		CWISS_UnpoisonMemory(old_slots, policy->slot->size * old_capacity);
		policy->alloc->free(
				old_ctrl,
				CWISS_AllocSize(old_capacity, policy->slot->size, policy->slot->align),
				policy->slot->align);
	}
}

/// Prunes control bits to remove as many tombstones as possible.
///
/// See the comment on `CWISS_RawTable_rehash_and_grow_if_necessary()`.
CWISS_INLINE_NEVER
static void CWISS_RawTable_DropDeletesWithoutResize(const CWISS_Policy* policy,
		CWISS_RawTable* self) {
	CWISS_DCHECK(CWISS_IsValidCapacity(self->capacity_), "invalid capacity: %zu",
			self->capacity_);
	CWISS_DCHECK(!CWISS_IsSmall(self->capacity_),
			"unexpected small capacity: %zu", self->capacity_);
	// Algorithm:
	// - mark all DELETED slots as EMPTY
	// - mark all FULL slots as DELETED
	// - for each slot marked as DELETED
	//     hash = Hash(element)
	//     target = find_first_non_full(hash)
	//     if target is in the same group
	//       mark slot as FULL
	//     else if target is EMPTY
	//       transfer element to target
	//       mark slot as EMPTY
	//       mark target as FULL
	//     else if target is DELETED
	//       swap current element with target element
	//       mark target as FULL
	//       repeat procedure for current slot with moved from element (target)
	CWISS_ConvertDeletedToEmptyAndFullToDeleted(self->ctrl_, self->capacity_);
	// Unfortunately because we do not know this size statically, we need to take
	// a trip to the allocator. Alternatively we could use a variable length
	// alloca...
	void* slot = policy->alloc->alloc(policy->slot->size, policy->slot->align);

	size_t i;
	for (i = 0; i != self->capacity_; i++) {
		if (!CWISS_IsDeleted(self->ctrl_[i])) continue;

		char* old_slot = self->slots_ + i * policy->slot->size;
		size_t hash = policy->key->hash(policy->slot->get(old_slot));

		const CWISS_FindInfo target =
			CWISS_FindFirstNonFull(self->ctrl_, hash, self->capacity_);
		const size_t new_i = target.offset;

		char* new_slot = self->slots_ + new_i * policy->slot->size;

		// Verify if the old and new i fall within the same group wrt the hash.
		// If they do, we don't need to move the object as it falls already in the
		// best probe we can.
		const size_t probe_offset =
			CWISS_ProbeSeq_Start(self->ctrl_, hash, self->capacity_).offset_;
#define CWISS_ProbeIndex(pos_) \
		(((pos_ - probe_offset) & self->capacity_) / CWISS_Group_kWidth)

		// Element doesn't move.
		if (CWISS_LIKELY(CWISS_ProbeIndex(new_i) == CWISS_ProbeIndex(i))) {
			CWISS_SetCtrl(i, CWISS_H2(hash), self->capacity_, self->ctrl_,
					self->slots_, policy->slot->size);
			continue;
		}
		if (CWISS_IsEmpty(self->ctrl_[new_i])) {
			// Transfer element to the empty spot.
			// SetCtrl poisons/unpoisons the slots so we have to call it at the
			// right time.
			CWISS_SetCtrl(new_i, CWISS_H2(hash), self->capacity_, self->ctrl_,
					self->slots_, policy->slot->size);
			policy->slot->transfer(new_slot, old_slot);
			CWISS_SetCtrl(i, CWISS_kEmpty, self->capacity_, self->ctrl_, self->slots_,
					policy->slot->size);
		}
		else {
			CWISS_DCHECK(CWISS_IsDeleted(self->ctrl_[new_i]),
					"bad ctrl value at %zu: %02x", new_i, self->ctrl_[new_i]);
			CWISS_SetCtrl(new_i, CWISS_H2(hash), self->capacity_, self->ctrl_,
					self->slots_, policy->slot->size);
			// Until we are done rehashing, DELETED marks previously FULL slots.
			// Swap i and new_i elements.

			policy->slot->transfer(slot, old_slot);
			policy->slot->transfer(old_slot, new_slot);
			policy->slot->transfer(new_slot, slot);
			--i;  // repeat
		}
#undef CWISS_ProbeSeq_Start_index
	}
	CWISS_RawTable_ResetGrowthLeft(policy, self);
	policy->alloc->free(slot, policy->slot->size, policy->slot->align);
}

/// Called whenever the table *might* need to conditionally grow.
///
/// This function is an optimization opportunity to perform a rehash even when
/// growth is unnecessary, because vacating tombstones is beneficial for
/// performance in the long-run.
static inline void CWISS_RawTable_rehash_and_grow_if_necessary(
		const CWISS_Policy* policy, CWISS_RawTable* self) {
	if (self->capacity_ == 0) {
		CWISS_RawTable_Resize(policy, self, 1);
	}
	else if (self->capacity_ > CWISS_Group_kWidth &&
			// Do these calculations in 64-bit to avoid overflow.
			self->size_ * UINT64_C(32) <= self->capacity_ * UINT64_C(25)) {
		// Squash DELETED without growing if there is enough capacity.
		//
		// Rehash in place if the current size is <= 25/32 of capacity_.
		// Rationale for such a high factor: 1) drop_deletes_without_resize() is
		// faster than resize, and 2) it takes quite a bit of work to add
		// tombstones.  In the worst case, seems to take approximately 4
		// insert/erase pairs to create a single tombstone and so if we are
		// rehashing because of tombstones, we can afford to rehash-in-place as
		// long as we are reclaiming at least 1/8 the capacity without doing more
		// than 2X the work.  (Where "work" is defined to be size() for rehashing
		// or rehashing in place, and 1 for an insert or erase.)  But rehashing in
		// place is faster per operation than inserting or even doubling the size
		// of the table, so we actually afford to reclaim even less space from a
		// resize-in-place.  The decision is to rehash in place if we can reclaim
		// at about 1/8th of the usable capacity (specifically 3/28 of the
		// capacity) which means that the total cost of rehashing will be a small
		// fraction of the total work.
		//
		// Here is output of an experiment using the BM_CacheInSteadyState
		// benchmark running the old case (where we rehash-in-place only if we can
		// reclaim at least 7/16*capacity_) vs. this code (which rehashes in place
		// if we can recover 3/32*capacity_).
		//
		// Note that although in the worst-case number of rehashes jumped up from
		// 15 to 190, but the number of operations per second is almost the same.
		//
		// Abridged output of running BM_CacheInSteadyState benchmark from
		// raw_hash_set_benchmark.   N is the number of insert/erase operations.
		//
		//      | OLD (recover >= 7/16        | NEW (recover >= 3/32)
		// size |    N/s LoadFactor NRehashes |    N/s LoadFactor NRehashes
		//  448 | 145284       0.44        18 | 140118       0.44        19
		//  493 | 152546       0.24        11 | 151417       0.48        28
		//  538 | 151439       0.26        11 | 151152       0.53        38
		//  583 | 151765       0.28        11 | 150572       0.57        50
		//  628 | 150241       0.31        11 | 150853       0.61        66
		//  672 | 149602       0.33        12 | 150110       0.66        90
		//  717 | 149998       0.35        12 | 149531       0.70       129
		//  762 | 149836       0.37        13 | 148559       0.74       190
		//  807 | 149736       0.39        14 | 151107       0.39        14
		//  852 | 150204       0.42        15 | 151019       0.42        15
		CWISS_RawTable_DropDeletesWithoutResize(policy, self);
	}
	else {
		// Otherwise grow the container.
		CWISS_RawTable_Resize(policy, self, self->capacity_ * 2 + 1);
	}
}

/// Prefetches the backing array to dodge potential TLB misses.
/// This is intended to overlap with execution of calculating the hash for a
/// key.
static inline void CWISS_RawTable_PrefetchHeapBlock(
		const CWISS_Policy* policy, const CWISS_RawTable* self) {
	CWISS_PREFETCH(self->ctrl_, 1);
}

/// Issues CPU prefetch instructions for the memory needed to find or insert
/// a key.
///
/// NOTE: This is a very low level operation and should not be used without
/// specific benchmarks indicating its importance.
static inline void CWISS_RawTable_Prefetch(const CWISS_Policy* policy,
		const CWISS_RawTable* self,
		const void* key) {
	(void)key;
#if CWISS_HAVE_PREFETCH
	CWISS_RawTable_PrefetchHeapBlock(policy, self);
	CWISS_ProbeSeq seq = CWISS_ProbeSeq_Start(self->ctrl_, policy->key->hash(key),
			self->capacity_);
	CWISS_PREFETCH(self->ctrl_ + seq.offset_, 3);
	CWISS_PREFETCH(self->ctrl_ + seq.offset_ * policy->slot->size, 3);
#endif
}

/// The return type of `CWISS_RawTable_PrepareInsert()`.
typedef struct {
	size_t index;
	bool inserted;
} CWISS_PrepareInsert;

/// Given the hash of a value not currently in the table, finds the next viable
/// slot index to insert it at.
///
/// If the table does not actually have space, UB.
CWISS_INLINE_NEVER
static size_t CWISS_RawTable_PrepareInsert(const CWISS_Policy* policy,
		CWISS_RawTable* self, size_t hash) {
	CWISS_FindInfo target =
		CWISS_FindFirstNonFull(self->ctrl_, hash, self->capacity_);
	if (CWISS_UNLIKELY(self->growth_left_ == 0 &&
				!CWISS_IsDeleted(self->ctrl_[target.offset]))) {
		CWISS_RawTable_rehash_and_grow_if_necessary(policy, self);
		target = CWISS_FindFirstNonFull(self->ctrl_, hash, self->capacity_);
	}
	self->size_++;
	self->growth_left_ -= CWISS_IsEmpty(self->ctrl_[target.offset]);
	CWISS_SetCtrl(target.offset, CWISS_H2(hash), self->capacity_, self->ctrl_,
			self->slots_, policy->slot->size);
	// infoz().RecordInsert(hash, target.probe_length);
	return target.offset;
}

/// Attempts to find `key` in the table; if it isn't found, returns where to
/// insert it, instead.
static inline CWISS_PrepareInsert CWISS_RawTable_FindOrPrepareInsert(
		const CWISS_Policy* policy, const CWISS_KeyPolicy* key_policy,
		CWISS_RawTable* self, const void* key) {
	CWISS_RawTable_PrefetchHeapBlock(policy, self);
	size_t hash = key_policy->hash(key);
	CWISS_ProbeSeq seq = CWISS_ProbeSeq_Start(self->ctrl_, hash, self->capacity_);
	while (true) {
		CWISS_Group g = CWISS_Group_new(self->ctrl_ + seq.offset_);
		CWISS_BitMask match = CWISS_Group_Match(&g, CWISS_H2(hash));
		uint32_t i;
		while (CWISS_BitMask_next(&match, &i)) {
			size_t idx = CWISS_ProbeSeq_offset(&seq, i);
			char* slot = self->slots_ + idx * policy->slot->size;
			if (CWISS_LIKELY(key_policy->eq(key, policy->slot->get(slot))))
				return (CWISS_PrepareInsert) { idx, false };
		}
		if (CWISS_LIKELY(CWISS_Group_MatchEmpty(&g).mask)) break;
		CWISS_ProbeSeq_next(&seq);
		CWISS_DCHECK(seq.index_ <= self->capacity_, "full table!");
	}
	return (CWISS_PrepareInsert) {
		CWISS_RawTable_PrepareInsert(policy, self, hash),
			true
	};
}

/// Prepares a slot to insert an element into.
///
/// This function does all the work of calling the appropriate policy functions
/// to initialize the slot.
static inline void* CWISS_RawTable_PreInsert(const CWISS_Policy* policy,
		CWISS_RawTable* self, size_t i) {
	void* dst = self->slots_ + i * policy->slot->size;
	policy->slot->init(dst);
	return policy->slot->get(dst);
}

/// Creates a new empty table with the given capacity.
static inline CWISS_RawTable CWISS_RawTable_new(const CWISS_Policy* policy,
		size_t capacity) {
	CWISS_RawTable self = {
		.ctrl_ = CWISS_EmptyGroup(),
	};

	if (capacity != 0) {
		self.capacity_ = CWISS_NormalizeCapacity(capacity);
		CWISS_RawTable_InitializeSlots(policy, &self);
	}

	return self;
}

/// Ensures that at least `n` more elements can be inserted without a resize
/// (although this function my itself resize and rehash the table).
static inline void CWISS_RawTable_reserve(const CWISS_Policy* policy,
		CWISS_RawTable* self, size_t n) {
	if (n <= self->size_ + self->growth_left_) {
		return;
	}

	n = CWISS_NormalizeCapacity(CWISS_GrowthToLowerboundCapacity(n));
	CWISS_RawTable_Resize(policy, self, n);

	// This is after resize, to ensure that we have completed the allocation
	// and have potentially sampled the hashtable.
	// infoz().RecordReservation(n);
}

/// Creates a duplicate of this table.
static inline CWISS_RawTable CWISS_RawTable_dup(const CWISS_Policy* policy,
		const CWISS_RawTable* self) {
	CWISS_RawTable copy = CWISS_RawTable_new(policy, 0);

	CWISS_RawTable_reserve(policy, &copy, self->size_);
	// Because the table is guaranteed to be empty, we can do something faster
	// than a full `insert`. In particular we do not need to take a trip to
	// `CWISS_RawTable_rehash_and_grow_if_necessary()` because we are already
	// big enough (since `self` is a priori) and tombstones cannot be created
	// during this process.
	CWISS_RawIter iter;
	for (iter = CWISS_RawTable_citer(policy, self);
			CWISS_RawIter_get(policy, &iter); CWISS_RawIter_next(policy, &iter)) {
		void* v = CWISS_RawIter_get(policy, &iter);
		size_t hash = policy->key->hash(v);

		CWISS_FindInfo target =
			CWISS_FindFirstNonFull(copy.ctrl_, hash, copy.capacity_);
		CWISS_SetCtrl(target.offset, CWISS_H2(hash), copy.capacity_, copy.ctrl_,
				copy.slots_, policy->slot->size);
		void* slot = CWISS_RawTable_PreInsert(policy, &copy, target.offset);
		policy->obj->copy(slot, v);
		// infoz().RecordInsert(hash, target.probe_length);
	}
	copy.size_ = self->size_;
	copy.growth_left_ -= self->size_;
	return copy;
}

/// Destroys this table, destroying its elements and freeing the backing array.
static inline void CWISS_RawTable_destroy(const CWISS_Policy* policy,
		CWISS_RawTable* self) {
	CWISS_RawTable_DestroySlots(policy, self);
}

/// Returns whether the table is empty.
static inline bool CWISS_RawTable_empty(const CWISS_Policy* policy,
		const CWISS_RawTable* self) {
	return !self->size_;
}

/// Returns the number of elements in the table.
static inline size_t CWISS_RawTable_size(const CWISS_Policy* policy,
		const CWISS_RawTable* self) {
	return self->size_;
}

/// Returns the total capacity of the table, which is different from the number
/// of elements that would cause it to get resized.
static inline size_t CWISS_RawTable_capacity(const CWISS_Policy* policy,
		const CWISS_RawTable* self) {
	return self->capacity_;
}

/// Clears the table, erasing every element contained therein.
static inline void CWISS_RawTable_clear(const CWISS_Policy* policy, CWISS_RawTable* self) {
	// Iterating over this container is O(bucket_count()). When bucket_count()
	// is much greater than size(), iteration becomes prohibitively expensive.
	// For clear() it is more important to reuse the allocated array when the
	// container is small because allocation takes comparatively long time
	// compared to destruction of the elements of the container. So we pick the
	// largest bucket_count() threshold for which iteration is still fast and
	// past that we simply deallocate the array.
	if (self->capacity_ > 127) {
		CWISS_RawTable_DestroySlots(policy, self);

		// infoz().RecordClearedReservation();
	} else if (self->capacity_) {
		if (policy->slot->del != NULL) {
			size_t i;
			for (i = 0; i != self->capacity_; i++) {
				if (CWISS_IsFull(self->ctrl_[i])) {
					policy->slot->del(self->slots_ + i * policy->slot->size);
				}
			}
		}

		self->size_ = 0;
		CWISS_ResetCtrl(self->capacity_, self->ctrl_, self->slots_,
				policy->slot->size);
		CWISS_RawTable_ResetGrowthLeft(policy, self);
	}
	CWISS_DCHECK(!self->size_, "size was still nonzero");
	// infoz().RecordStorageChanged(0, capacity_);
}

/// The return type of `CWISS_RawTable_insert()`.
typedef struct {
	/// An iterator referring to the relevant element.
	CWISS_RawIter iter;
	/// True if insertion actually occurred; false if the element was already
	/// present.
	bool inserted;
} CWISS_Insert;

/// "Inserts" `val` into the table if it isn't already present.
///
/// This function does not perform insertion; it behaves exactly like
/// `CWISS_RawTable_insert()` up until it would copy-initialize the new
/// element, instead returning a valid iterator pointing to uninitialized data.
///
/// This allows, for example, lazily constructing the parts of the element that
/// do not figure into the hash or equality.
///
/// If this function returns `true` in `inserted`, the caller has *no choice*
/// but to insert, i.e., they may not change their minds at that point.
///
/// `key_policy` is a possibly heterogenous key policy for comparing `key`'s
/// type to types in the map. `key_policy` may be `&policy->key`.
static inline CWISS_Insert CWISS_RawTable_deferred_insert(
		const CWISS_Policy* policy, const CWISS_KeyPolicy* key_policy,
		CWISS_RawTable* self, const void* key) {
	CWISS_PrepareInsert res =
		CWISS_RawTable_FindOrPrepareInsert(policy, key_policy, self, key);

	if (res.inserted) {
		CWISS_RawTable_PreInsert(policy, self, res.index);
	}
	return (CWISS_Insert) {
		CWISS_RawTable_citer_at(policy, self, res.index),
			res.inserted
	};
}

/// Inserts `val` (by copy) into the table if it isn't already present.
///
/// Returns an iterator pointing to the element in the map and whether it was
/// just inserted or was already present.
static inline CWISS_Insert CWISS_RawTable_insert(const CWISS_Policy* policy,
		CWISS_RawTable* self,
		const void* val) {
	CWISS_PrepareInsert res =
		CWISS_RawTable_FindOrPrepareInsert(policy, policy->key, self, val);

	if (res.inserted) {
		void* slot = CWISS_RawTable_PreInsert(policy, self, res.index);
		policy->obj->copy(slot, val);
	}
	return (CWISS_Insert) {
		CWISS_RawTable_citer_at(policy, self, res.index),
			res.inserted
	};
}

/// Tries to find the corresponding entry for `key` using `hash` as a hint.
/// If not found, returns a null iterator.
///
/// `key_policy` is a possibly heterogenous key policy for comparing `key`'s
/// type to types in the map. `key_policy` may be `&policy->key`.
///
/// If `hash` is not actually the hash of `key`, UB.
static inline CWISS_RawIter CWISS_RawTable_find_hinted(
		const CWISS_Policy* policy, const CWISS_KeyPolicy* key_policy,
		const CWISS_RawTable* self, const void* key, size_t hash) {
	CWISS_ProbeSeq seq = CWISS_ProbeSeq_Start(self->ctrl_, hash, self->capacity_);
	while (true) {
		CWISS_Group g = CWISS_Group_new(self->ctrl_ + seq.offset_);
		CWISS_BitMask match = CWISS_Group_Match(&g, CWISS_H2(hash));
		uint32_t i;
		while (CWISS_BitMask_next(&match, &i)) {
			char* slot =
				self->slots_ + CWISS_ProbeSeq_offset(&seq, i) * policy->slot->size;
			if (CWISS_LIKELY(key_policy->eq(key, policy->slot->get(slot))))
				return CWISS_RawTable_citer_at(policy, self,
						CWISS_ProbeSeq_offset(&seq, i));
		}
		if (CWISS_LIKELY(CWISS_Group_MatchEmpty(&g).mask))
			return (CWISS_RawIter) { 0 };
		CWISS_ProbeSeq_next(&seq);
		CWISS_DCHECK(seq.index_ <= self->capacity_, "full table!");
	}
}

/// Tries to find the corresponding entry for `key`.
/// If not found, returns a null iterator.
///
/// `key_policy` is a possibly heterogenous key policy for comparing `key`'s
/// type to types in the map. `key_policy` may be `&policy->key`.
static inline CWISS_RawIter CWISS_RawTable_find(
		const CWISS_Policy* policy, const CWISS_KeyPolicy* key_policy,
		const CWISS_RawTable* self, const void* key) {
	return CWISS_RawTable_find_hinted(policy, key_policy, self, key,
			key_policy->hash(key));
}

/// Erases the element pointed to by the given valid iterator.
/// This function will invalidate the iterator.
static inline void CWISS_RawTable_erase_at(const CWISS_Policy* policy,
		CWISS_RawIter it) {
	CWISS_AssertIsFull(it.ctrl_);
	if (policy->slot->del != NULL) {
		policy->slot->del(it.slot_);
	}
	CWISS_RawTable_EraseMetaOnly(policy, it);
}

/// Erases the entry corresponding to `key`, if present. Returns true if
/// deletion occured.
///
/// `key_policy` is a possibly heterogenous key policy for comparing `key`'s
/// type to types in the map. `key_policy` may be `&policy->key`.
static inline bool CWISS_RawTable_erase(const CWISS_Policy* policy,
		const CWISS_KeyPolicy* key_policy,
		CWISS_RawTable* self, const void* key) {
	CWISS_RawIter it = CWISS_RawTable_find(policy, key_policy, self, key);
	if (it.slot_ == NULL) return false;
	CWISS_RawTable_erase_at(policy, it);
	return true;
}

/// Triggers a rehash, growing to at least a capacity of `n`.
static inline void CWISS_RawTable_rehash(const CWISS_Policy* policy,
		CWISS_RawTable* self, size_t n) {
	if (n == 0 && self->capacity_ == 0) return;
	if (n == 0 && self->size_ == 0) {
		CWISS_RawTable_DestroySlots(policy, self);
		// infoz().RecordStorageChanged(0, 0);
		// infoz().RecordClearedReservation();
		return;
	}

	// bitor is a faster way of doing `max` here. We will round up to the next
	// power-of-2-minus-1, so bitor is good enough.
	size_t m = CWISS_NormalizeCapacity(
			n | CWISS_GrowthToLowerboundCapacity(self->size_));
	// n == 0 unconditionally rehashes as per the standard.
	if (n == 0 || m > self->capacity_) {
		CWISS_RawTable_Resize(policy, self, m);

		// This is after resize, to ensure that we have completed the allocation
		// and have potentially sampled the hashtable.
		// infoz().RecordReservation(n);
	}
}

/// Returns whether `key` is contained in this table.
///
/// `key_policy` is a possibly heterogenous key policy for comparing `key`'s
/// type to types in the map. `key_policy` may be `&policy->key`.
static inline bool CWISS_RawTable_contains(const CWISS_Policy* policy,
		const CWISS_KeyPolicy* key_policy,
		const CWISS_RawTable* self,
		const void* key) {
	return CWISS_RawTable_find(policy, key_policy, self, key).slot_ != NULL;
}

CWISS_END_EXTERN
CWISS_END
/// cwisstable/internal/raw_table.h ////////////////////////////////////////////

/// cwisstable/declare.h ///////////////////////////////////////////////////////
/// SwissTable code generation macros.
///
/// This file is the entry-point for users of `cwisstable`. It exports six
/// macros for generating different kinds of tables. Four correspond to Abseil's
/// four SwissTable containers:
///
/// - `CWISS_DECLARE_FLAT_HASHSET(Set, Type)`
/// - `CWISS_DECLARE_FLAT_HASHMAP(Map, Key, Value)`
/// - `CWISS_DECLARE_NODE_HASHSET(Set, Type)`
/// - `CWISS_DECLARE_NODE_HASHMAP(Map, Key, Value)`
///
/// These expand to a type (with the same name as the first argument) and and
/// a collection of strongly-typed functions associated to it (the generated
/// API is described below). These macros use the default policy (see policy.h)
/// for each of the four containers; custom policies may be used instead via
/// the following macros:
///
/// - `CWISS_DECLARE_HASHSET_WITH(Set, Type, kPolicy)`
/// - `CWISS_DECLARE_HASHMAP_WITH(Map, Key, Value, kPolicy)`
///
/// `kPolicy` must be a constant global variable referring to an appropriate
/// property for the element types of the container.
///
/// The generated API is safe: the functions are well-typed and automatically
/// pass the correct policy pointer. Because the pointer is a constant
/// expression, it promotes devirtualization when inlining.
///
/// # Generated API
///
/// See `set_api.h` and `map_api.h` for detailed listings of what the generated
/// APIs look like.

CWISS_BEGIN
CWISS_BEGIN_EXTERN

/// Generates a new hash set type with inline storage and the default
/// plain-old-data policies.
///
/// See header documentation for examples of generated API.
#define CWISS_DECLARE_FLAT_HASHSET(HashSet_, Type_,obj_copy, obj_dtor, key_hash, key_eq)          \
	CWISS_DECLARE_FLAT_SET_POLICY(HashSet_##_kPolicy, Type_, obj_copy, obj_dtor, key_hash, key_eq); \
	CWISS_DECLARE_HASHSET_WITH(HashSet_, Type_, HashSet_##_kPolicy)

#define CWISS_DECLARE_FLAT_HASHSET_DEFAULT(HashSet_, Type_)         \
	static inline void HashSet_##_default_dtor(void* val) { } \
	static inline void HashSet_##_default_copy(void* dst_, const void* src_) { \
		memcpy(dst_, src_, sizeof(Type_));            \
	} \
	static inline size_t HashSet_##_default_hash(const void* val) { \
		CWISS_AbslHash_State state = CWISS_AbslHash_kInit;            \
		CWISS_AbslHash_Write(&state, val, sizeof(Type_));              \
		return CWISS_AbslHash_Finish(state);                          \
	} \
	static inline bool HashSet_##_default_eq(const void* a, const void* b) { return memcmp (a,b,sizeof(Type_)) == 0; } \
	CWISS_DECLARE_FLAT_HASHSET(HashSet_, Type_, \
			HashSet_##_default_copy, \
			HashSet_##_default_dtor, \
			HashSet_##_default_hash, \
			HashSet_##_default_eq);

/// Generates a new hash set type with outline storage and the default
/// plain-old-data policies.
///
/// See header documentation for examples of generated API.
#define CWISS_DECLARE_NODE_HASHSET(HashSet_, Type_, obj_copy, obj_dtor, key_hash, key_eq)          \
	CWISS_DECLARE_NODE_SET_POLICY(HashSet_##_kPolicy, Type_, obj_copy, obj_dtor, key_hash, key_eq); \
	CWISS_DECLARE_HASHSET_WITH(HashSet_, Type_, HashSet_##_kPolicy)

#define CWISS_DECLARE_NODE_HASHSET_DEFAULT(HashSet_, Type_)         \
	static inline void HashSet_##_default_dtor(void* val) { } \
	static inline void HashSet_##_default_copy(void* dst_, const void* src_) { \
		memcpy(dst_, src_, sizeof(Type_));            \
	} \
	static inline size_t HashSet_##_default_hash(const void* val) { \
		CWISS_AbslHash_State state = CWISS_AbslHash_kInit;            \
		CWISS_AbslHash_Write(&state, val, sizeof(Type_));              \
		return CWISS_AbslHash_Finish(state);                          \
	} \
	static inline bool HashSet_##_default_eq(const void* a, const void* b) { return memcmp (a,b,sizeof(Type_)) == 0; } \
	CWISS_DECLARE_NODE_HASHSET(HashSet_, Type_, \
			HashSet_##_default_copy, \
			HashSet_##_default_dtor, \
			HashSet_##_default_hash, \
			HashSet_##_default_eq);

/// Generates a new hash map type with inline storage and the default
/// plain-old-data policies.
///
/// See header documentation for examples of generated API.
#define CWISS_DECLARE_FLAT_HASHMAP(HashMap_, K_, V_, obj_copy, obj_dtor, key_hash, key_eq)         \
	CWISS_DECLARE_FLAT_MAP_POLICY(HashMap_##_kPolicy, K_, V_, obj_copy, obj_dtor, key_hash, key_eq); \
	CWISS_DECLARE_HASHMAP_WITH(HashMap_, K_, V_, HashMap_##_kPolicy)

#define CWISS_DECLARE_FLAT_HASHMAP_DEFAULT(HashMap_, K_, V_)         \
	static inline void HashMap_##_default_dtor(void* val) { } \
	typedef struct {                                           \
		K_ k;                                                    \
		V_ v;                                                    \
	} HashMap_##_EntryInternal;                                      \
	static inline void HashMap_##_default_copy(void* dst_, const void* src_) { \
		memcpy(dst_, src_, sizeof(HashMap_##_EntryInternal));            \
	} \
	static inline size_t HashMap_##_default_hash(const void* val) { \
		CWISS_AbslHash_State state = CWISS_AbslHash_kInit;            \
		CWISS_AbslHash_Write(&state, val, sizeof(K_));              \
		return CWISS_AbslHash_Finish(state);                          \
	} \
	static inline bool HashMap_##_default_eq(const void* a, const void* b) { return memcmp (a,b,sizeof(K_)) == 0; } \
	CWISS_DECLARE_FLAT_HASHMAP(HashMap_, K_, V_, \
			HashMap_##_default_copy, \
			HashMap_##_default_dtor, \
			HashMap_##_default_hash, \
			HashMap_##_default_eq);

/// Generates a new hash map type with outline storage and the default
/// plain-old-data policies.
///
/// See header documentation for examples of generated API.
#define CWISS_DECLARE_NODE_HASHMAP(HashMap_, K_, V_, a,b,c,d)                 \
	CWISS_DECLARE_NODE_MAP_POLICY(HashMap_##_kPolicy, K_, V_, a,b,c,d); \
	CWISS_DECLARE_HASHMAP_WITH(HashMap_, K_, V_, HashMap_##_kPolicy)

#define CWISS_DECLARE_NODE_HASHMAP_DEFAULT(HashMap_, K_, V_)         \
	typedef struct {                                           \
		K_ k;                                                    \
		V_ v;                                                    \
	} HashMap_##_EntryInternal;                                      \
	static inline void HashMap_##_default_dtor(void* val) { } \
	static inline void HashMap_##_default_copy(void* dst_, const void* src_) { \
		memcpy(dst_, src_, sizeof(HashMap_##_EntryInternal));            \
	} \
	static inline size_t HashMap_##_default_hash(const void* val) { \
		CWISS_AbslHash_State state = CWISS_AbslHash_kInit;            \
		CWISS_AbslHash_Write(&state, val, sizeof(K_));              \
		return CWISS_AbslHash_Finish(state);                          \
	} \
	static inline bool HashMap_##_default_eq(const void* a, const void* b) { return memcmp (a,b,sizeof(K_)) == 0; } \
	CWISS_DECLARE_NODE_HASHMAP(HashMap_, K_, V_, \
			HashMap_##_default_copy, \
			HashMap_##_default_dtor, \
			HashMap_##_default_hash, \
			HashMap_##_default_eq);

/// Generates a new hash set type using the given policy.
///
/// See header documentation for examples of generated API.
#define CWISS_DECLARE_HASHSET_WITH(HashSet_, Type_, kPolicy_) \
	typedef Type_ HashSet_##_Entry;                             \
	typedef Type_ HashSet_##_Key;                               \
	CWISS_DECLARE_COMMON_(HashSet_, HashSet_##_Entry, HashSet_##_Key, kPolicy_)

/// Generates a new hash map type using the given policy.
///
/// See header documentation for examples of generated API.
#define CWISS_DECLARE_HASHMAP_WITH(HashMap_, K_, V_, kPolicy_) \
	typedef struct HashMap_##_entry_t {                                \
		K_ key;                                                    \
		V_ val;                                                    \
	} HashMap_##_Entry;                                          \
	typedef K_ HashMap_##_Key;                                   \
	CWISS_DECLARE_COMMON_(HashMap_, HashMap_##_Entry, HashMap_##_Key, kPolicy_)

/// Declares a heterogenous lookup for an existing SwissTable type.
///
/// This macro will expect to find the following functions:
///   - size_t <Table>_<Key>_hash(const Key*);
///   - bool <Table>_<Key>_eq(const Key*, const <Table>_Key*);
///
/// These functions will be used to build the heterogenous key policy.
#define CWISS_DECLARE_LOOKUP(HashSet_, Key_) \
	CWISS_DECLARE_LOOKUP_NAMED(HashSet_, Key_, Key_)

/// Declares a heterogenous lookup for an existing SwissTable type.
///
/// This is like `CWISS_DECLARE_LOOKUP`, but allows customizing the name used
/// in the `_by_` prefix on the names, as well as the names of the extension
/// point functions.
#define CWISS_DECLARE_LOOKUP_NAMED(HashSet_, LookupName_, Key_)                \
	CWISS_BEGIN                                                                  \
static inline size_t HashSet_##_##LookupName_##_SyntheticHash(               \
		const void* val) {                                                       \
	return HashSet_##_##LookupName_##_hash((const Key_*)val);                  \
	}                                                                            \
	static inline bool HashSet_##_##LookupName_##_SyntheticEq(const void* a,     \
			const void* b) {   \
		return HashSet_##_##LookupName_##_eq((const Key_*)a,                       \
				(const HashSet_##_Entry*)b);          \
	}                                                                            \
	static const CWISS_KeyPolicy HashSet_##_##LookupName_##_kPolicy = {          \
		HashSet_##_##LookupName_##_SyntheticHash,                                \
		HashSet_##_##LookupName_##_SyntheticEq,                                  \
	};                                                                           \
	\
	static inline const CWISS_KeyPolicy* HashSet_##_##LookupName_##_policy(      \
			void) {                                                                  \
		return &HashSet_##_##LookupName_##_kPolicy;                                \
	}                                                                            \
	\
	static inline HashSet_##_Insert HashSet_##_deferred_insert_by_##LookupName_( \
			HashSet_* self, const Key_* key) {                                       \
		CWISS_Insert ret = CWISS_RawTable_deferred_insert(                         \
				HashSet_##_policy(), &HashSet_##_##LookupName_##_kPolicy, &self->set_, \
				key);                                                                  \
		return (HashSet_##_Insert){{ret.iter}, ret.inserted};                      \
	}                                                                            \
	static inline HashSet_##_CIter HashSet_##_cfind_hinted_by_##LookupName_(     \
			const HashSet_* self, const Key_* key, size_t hash) {                    \
		return (HashSet_##_CIter){CWISS_RawTable_find_hinted(                      \
				HashSet_##_policy(), &HashSet_##_##LookupName_##_kPolicy, &self->set_, \
				key, hash)};                                                           \
	}                                                                            \
	static inline HashSet_##_Iter HashSet_##_find_hinted_by_##LookupName_(       \
			HashSet_* self, const Key_* key, size_t hash) {                          \
		return (HashSet_##_Iter){CWISS_RawTable_find_hinted(                       \
				HashSet_##_policy(), &HashSet_##_##LookupName_##_kPolicy, &self->set_, \
				key, hash)};                                                           \
	}                                                                            \
	\
	static inline HashSet_##_CIter HashSet_##_cfind_by_##LookupName_(            \
			const HashSet_* self, const Key_* key) {                                 \
		return (HashSet_##_CIter){CWISS_RawTable_find(                             \
				HashSet_##_policy(), &HashSet_##_##LookupName_##_kPolicy, &self->set_, \
				key)};                                                                 \
	}                                                                            \
	static inline HashSet_##_Iter HashSet_##_find_by_##LookupName_(              \
			HashSet_* self, const Key_* key) {                                       \
		return (HashSet_##_Iter){CWISS_RawTable_find(                              \
				HashSet_##_policy(), &HashSet_##_##LookupName_##_kPolicy, &self->set_, \
				key)};                                                                 \
	}                                                                            \
	\
	static inline bool HashSet_##_contains_by_##LookupName_(                     \
			const HashSet_* self, const Key_* key) {                                 \
		return CWISS_RawTable_contains(HashSet_##_policy(),                        \
				&HashSet_##_##LookupName_##_kPolicy,        \
				&self->set_, key);                          \
	}                                                                            \
	\
	static inline bool HashSet_##_erase_by_##LookupName_(HashSet_* self,         \
			const Key_* key) {      \
		return CWISS_RawTable_erase(HashSet_##_policy(),                           \
				&HashSet_##_##LookupName_##_kPolicy,           \
				&self->set_, key);                             \
	}                                                                            \
	\
	CWISS_END                                                                    \
	/* Force a semicolon. */                                                     \
	struct HashSet_##_##LookupName_##_NeedsTrailingSemicolon_ {                  \
		int x;                                                                     \
	}

// ---- PUBLIC API ENDS HERE! ----

#define CWISS_DECLARE_COMMON_(HashSet_, Type_, Key_, kPolicy_)                 \
	CWISS_BEGIN                                                                  \
	static inline SDB_MAYBE_UNUSED const CWISS_Policy* HashSet_##_policy(void) {                  \
		return &kPolicy_;                                                          \
	}                                                                            \
	\
	typedef struct HashSet_##_t {                                                      \
		CWISS_RawTable set_;                                                       \
	} HashSet_;                                                                  \
	\
	static inline SDB_MAYBE_UNUSED HashSet_ HashSet_##_new(size_t bucket_count) {                 \
		return (HashSet_){CWISS_RawTable_new(&kPolicy_, bucket_count)};            \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED HashSet_ HashSet_##_dup(const HashSet_* that) {                \
		return (HashSet_){CWISS_RawTable_dup(&kPolicy_, &that->set_)};             \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED void HashSet_##_destroy(HashSet_* self) {                      \
		CWISS_RawTable_destroy(&kPolicy_, &self->set_);                            \
	}                                                                            \
	\
	typedef struct {                                                             \
		CWISS_RawIter it_;                                                         \
	} HashSet_##_Iter;                                                           \
	static inline SDB_MAYBE_UNUSED HashSet_##_Iter HashSet_##_iter(HashSet_* self) {              \
		return (HashSet_##_Iter){CWISS_RawTable_iter(&kPolicy_, &self->set_)};     \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED Type_* HashSet_##_Iter_get(const HashSet_##_Iter* it) {        \
		return (Type_*)CWISS_RawIter_get(&kPolicy_, &it->it_);                     \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED Type_* HashSet_##_Iter_next(HashSet_##_Iter* it) {             \
		return (Type_*)CWISS_RawIter_next(&kPolicy_, &it->it_);                    \
	}                                                                            \
	\
	typedef struct {                                                             \
		CWISS_RawIter it_;                                                         \
	} HashSet_##_CIter;                                                          \
	static inline SDB_MAYBE_UNUSED HashSet_##_CIter HashSet_##_citer(const HashSet_* self) {      \
		return (HashSet_##_CIter){CWISS_RawTable_citer(&kPolicy_, &self->set_)};   \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED const Type_* HashSet_##_CIter_get(                             \
			const HashSet_##_CIter* it) {                                            \
		return (const Type_*)CWISS_RawIter_get(&kPolicy_, &it->it_);               \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED const Type_* HashSet_##_CIter_next(HashSet_##_CIter* it) {     \
		return (const Type_*)CWISS_RawIter_next(&kPolicy_, &it->it_);              \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED HashSet_##_CIter HashSet_##_Iter_const(HashSet_##_Iter it) {   \
		return (HashSet_##_CIter){it.it_};                                         \
	}                                                                            \
	\
	static inline SDB_MAYBE_UNUSED void HashSet_##_reserve(HashSet_* self, size_t n) {            \
		CWISS_RawTable_reserve(&kPolicy_, &self->set_, n);                         \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED void HashSet_##_rehash(HashSet_* self, size_t n) {             \
		CWISS_RawTable_rehash(&kPolicy_, &self->set_, n);                          \
	}                                                                            \
	\
	static inline SDB_MAYBE_UNUSED bool HashSet_##_empty(const HashSet_* self) {                  \
		return CWISS_RawTable_empty(&kPolicy_, &self->set_);                       \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED size_t HashSet_##_size(const HashSet_* self) {                 \
		return CWISS_RawTable_size(&kPolicy_, &self->set_);                        \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED size_t HashSet_##_capacity(const HashSet_* self) {             \
		return CWISS_RawTable_capacity(&kPolicy_, &self->set_);                    \
	}                                                                            \
	\
	static inline SDB_MAYBE_UNUSED void HashSet_##_clear(HashSet_* self) {                        \
		CWISS_RawTable_clear(&kPolicy_, &self->set_);                       \
	}                                                                            \
	\
	typedef struct {                                                             \
		HashSet_##_Iter iter;                                                      \
		bool inserted;                                                             \
	} HashSet_##_Insert;                                                         \
	static inline SDB_MAYBE_UNUSED HashSet_##_Insert HashSet_##_deferred_insert(                  \
			HashSet_* self, const Key_* key) {                                       \
		CWISS_Insert ret = CWISS_RawTable_deferred_insert(&kPolicy_, kPolicy_.key, \
				&self->set_, key);       \
		return (HashSet_##_Insert){{ret.iter}, ret.inserted};                      \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED HashSet_##_Insert HashSet_##_insert(HashSet_* self,            \
			const Type_* val) {        \
		CWISS_Insert ret = CWISS_RawTable_insert(&kPolicy_, &self->set_, val);     \
		return (HashSet_##_Insert){{ret.iter}, ret.inserted};                      \
	}                                                                            \
	\
	static inline SDB_MAYBE_UNUSED HashSet_##_CIter HashSet_##_cfind_hinted(                      \
			const HashSet_* self, const Key_* key, size_t hash) {                    \
		return (HashSet_##_CIter){CWISS_RawTable_find_hinted(                      \
				&kPolicy_, kPolicy_.key, &self->set_, key, hash)};                     \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED HashSet_##_Iter HashSet_##_find_hinted(                        \
			HashSet_* self, const Key_* key, size_t hash) {                          \
		return (HashSet_##_Iter){CWISS_RawTable_find_hinted(                       \
				&kPolicy_, kPolicy_.key, &self->set_, key, hash)};                     \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED HashSet_##_CIter HashSet_##_cfind(const HashSet_* self,        \
			const Key_* key) {           \
		return (HashSet_##_CIter){                                                 \
			CWISS_RawTable_find(&kPolicy_, kPolicy_.key, &self->set_, key)};       \
	}                                                                            \
	static inline SDB_MAYBE_UNUSED HashSet_##_Iter HashSet_##_find(HashSet_* self,                \
			const Key_* key) {             \
		return (HashSet_##_Iter){                                                  \
			CWISS_RawTable_find(&kPolicy_, kPolicy_.key, &self->set_, key)};       \
	}                                                                            \
	\
	static inline bool SDB_MAYBE_UNUSED HashSet_##_contains(const HashSet_* self,                 \
			const Key_* key) {                    \
		return CWISS_RawTable_contains(&kPolicy_, kPolicy_.key, &self->set_, key); \
	}                                                                            \
	\
	static inline void SDB_MAYBE_UNUSED HashSet_##_erase_at(HashSet_##_Iter it) {                 \
		CWISS_RawTable_erase_at(&kPolicy_, it.it_);                                \
	}                                                                            \
	static inline bool SDB_MAYBE_UNUSED HashSet_##_erase(HashSet_* self, const Key_* key) {       \
		return CWISS_RawTable_erase(&kPolicy_, kPolicy_.key, &self->set_, key);    \
	}                                                                            \
	\
	CWISS_END                                                                    \
	/* Force a semicolon. */ struct HashSet_##_NeedsTrailingSemicolon_ { int x; }

CWISS_END_EXTERN
CWISS_END
/// cwisstable/declare.h ///////////////////////////////////////////////////////

#endif  // CWISSTABLE_H_
