#ifndef R2_TYPES_BASE_H
#define R2_TYPES_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <sys/types.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#define cut8 const uint8_t
#define ut64 uint64_t
#define st64 int64_t
#define ut32 uint32_t
#define st32 int32_t
#define ut16 uint16_t
#define st16 int16_t
#define ut8 uint8_t
#define st8 int8_t

#if defined(_MSC_VER)
# define R_ALIGNED(x) __declspec(align(x))
#else
# define R_ALIGNED(x) __attribute__((aligned(x)))
#endif

#if defined(__GNUC__)
#define R_LIKELY(x) __builtin_expect((size_t)(x),1)
#define R_UNLIKELY(x) __builtin_expect((size_t)(x),0)
#define R_MUSTUSE __attribute__((warn_unused_result))
#else
#define R_LIKELY(x) (size_t)(x)
#define R_UNLIKELY(x) (size_t)(x)
#define R_MUSTUSE
#endif

#define R_IGNORE_RETURN(x) if ((x)) {;}

// unaligned word access
typedef R_ALIGNED(1) ut16 uut16;
typedef R_ALIGNED(1) ut32 uut32;
typedef R_ALIGNED(1) ut64 uut64;
typedef R_ALIGNED(1) st16 ust16;
typedef R_ALIGNED(1) st32 ust32;
typedef R_ALIGNED(1) st64 ust64;

typedef union {
	ut8 v8;
	ut16 v16;
	ut32 v32;
	ut64 v64;
} utAny;

typedef struct _ut80 {
	ut64 Low;
	ut16 High;
} ut80;
typedef struct _ut96 {
	ut64 Low;
	ut32 High;
} ut96;
typedef struct _ut128 {
	ut64 Low;
	st64 High;
} ut128;
typedef struct _ut256 {
	ut128 Low;
	ut128 High;
} ut256;
typedef struct _utX {
	ut80 v80;
	ut96 v96;
	ut128 v128;
	ut256 v256;
} utX;

#include <stdbool.h>

/* limits */
#undef UT64_MAX
#undef UT64_GT0
#undef UT64_LT0
#undef UT64_MIN
#undef UT32_MAX
#undef UT32_MIN
#undef UT16_MIN
#undef UT8_MIN
#define ST64_MAX ((st64)0x7FFFFFFFFFFFFFFFULL)
#define ST64_MIN ((st64)(-ST64_MAX-1))
#define UT64_MAX ((ut64)0xFFFFFFFFFFFFFFFFULL)
#define UT64_GT0 ((ut64)0x8000000000000000ULL)
#define UT64_LT0 ((ut64)0x7FFFFFFFFFFFFFFFULL)
#define UT64_MIN 0ULL
#define UT64_32U 0xFFFFFFFF00000000ULL
#define UT64_16U 0xFFFFFFFFFFFF0000ULL
#define UT64_8U  0xFFFFFFFFFFFFFF00ULL
#define UT32_MIN 0U
#define UT16_MIN 0U
#define UT32_GT0 0x80000000U
#define UT32_LT0 0x7FFFFFFFU
#define ST32_MAX 0x7FFFFFFF
#define ST32_MIN (-ST32_MAX-1)
#define UT32_MAX 0xFFFFFFFFU
#define UT32_MIN 0U
#define ST16_MAX 0x7FFF
#define ST16_MIN (-ST16_MAX-1)
#define UT16_GT0 0x8000U
#define UT16_MAX 0xFFFFU
#define ST8_MAX  0x7F
#define ST8_MIN  (-ST8_MAX - 1)
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU
#define UT8_MIN  0x00U
#define ASCII_MIN 32
#define ASCII_MAX 127

#define UT24_MAX 0xFFFFFF
#define UT40_MAX 0xFFFFFFFFFF
#define UT48_MAX 0xFFFFFFFFFFFF
#define UT56_MAX 0xFFFFFFFFFFFFFF

#if SSIZE_MAX == ST32_MAX
#define SZT_MAX  UT32_MAX
#define SZT_MIN  UT32_MIN
#define SSZT_MAX  ST32_MAX
#define SSZT_MIN  ST32_MIN
#else
#define SZT_MAX  UT64_MAX
#define SZT_MIN  UT64_MIN
#define SSZT_MAX  ST64_MAX
#define SSZT_MIN  ST64_MIN
#endif

#define UT64_ALIGN(x) (x + (x - (x % sizeof (ut64))))
#define UT32_ALIGN(x) (x + (x - (x % sizeof (ut32))))
#define UT16_ALIGN(x) (x + (x - (x % sizeof (ut16))))

#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_HI(x) ((ut32)(((ut64)(x))>>32)&UT32_MAX)

#define R_BETWEEN(x,y,z) (((y)>=(x)) && ((y)<=(z)))
#define R_ROUND(x,y) ((x)%(y))?(x)+((y)-((x)%(y))):(x)
#define R_DIM(x,y,z) (((x)<(y))?(y):((x)>(z))?(z):(x))
#ifndef R_MAX_DEFINED
#define R_MAX(x,y) (((x)>(y))?(x):(y))
#define R_MAX_DEFINED
#endif
#ifndef R_MIN_DEFINED
#define R_MIN(x,y) (((x)>(y))?(y):(x))
#define R_MIN_DEFINED
#endif
#define R_ABS(x) (((x)<0)?-(x):(x))
#define R_BTW(x,y,z) (((x)>=(y))&&((y)<=(z)))?y:x

#include "r_types_overflow.h"

/* copied from bithacks.h */
#define B_IS_SET(x, n)   (((x) & (1ULL << (n)))? 1: 0)
#define B_SET(x, n)      ((x) |= (1ULL << (n)))
#define B_EVEN(x)        (((x) & 1) == 0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_UNSET(x, n)    ((x) &= ~(1ULL << (n)))
#define B_TOGGLE(x, n)   ((x) ^= (1ULL << (n)))

#define B11111 31
#define B11110 30
#define B11101 29
#define B11100 28
#define B11011 27
#define B11010 26
#define B11001 25
#define B11000 24
#define B10111 23
#define B10110 22
#define B10101 21
#define B10100 20
#define B10011 19
#define B10010 18
#define B10001 17
#define B10000 16
#define B1111 15
#define B1110 14
#define B1101 13
#define B1100 12
#define B1011 11
#define B1010 10
#define B1001 9
#define B1000 8
#define B0111 7
#define B0110 6
#define B0101 5
#define B0100 4
#define B0011 3
#define B0010 2
#define B0001 1
#define B0000 0
#undef B
#define B4(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))

/* portable non-c99 inf/nan types */
#ifndef INFINITY
#define INFINITY (1.0f/0.0f)
#endif

#ifndef NAN
#define NAN (0.0f/0.0f)
#endif

#define F32_NAN   (strtof("NAN", NULL))
#define F32_PINF  (strtof("INF", NULL))
#define F32_NINF  (-strtof("INF", NULL))
#define F64_NAN   (strtod("NAN", NULL))
#define F64_PINF  (strtod("INF", NULL))
#define F64_NINF  (-strtod("INF", NULL))
#define F128_NAN  (strtold("NAN", NULL))
#define F128_PINF (strtold("INF", NULL))
#define F128_NINF (-strtold("INF", NULL))

/* A workaround against libc headers redefinition of __attribute__:
 * Standard include has lines like
 * #if (GCC_VERSION < 2007)
 * # define __attribute__(x)
 * #endif
 * So we have do remove this define for TinyCC compiler
 */
#if defined(__TINYC__) && (GCC_VERSION < 2007)
#undef __attribute__
#endif

#ifdef _MSC_VER
#define R_PACKED( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#elif defined(__GNUC__) || defined(__TINYC__)
#define R_PACKED( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

#define R_UNWRAP2(a,b) ((a)? a->b: NULL)
#define R_UNWRAP3(a,b,c) ((a)? a->b? a->b->c: NULL: NULL)
#define R_UNWRAP4(a,b,c,d) ((a)? a->b? a->b->c? a->b->c->d: NULL: NULL: NULL)
#define R_UNWRAP5(a,b,c,d,e) ((a)? a->b? a->b->c? a->b->c->d? a->b->c->d->e: NULL: NULL: NULL: NULL)
#define R_UNWRAP6(a,b,c,d,e,f) ((a)? a->b? a->b->c? a->b->c->d? a->b->c->d->e? a->b->c->d->e: NULL: NULL: NULL: NULL: NULL)

#ifdef __GNUC__
#define R_UNUSED __attribute__((__unused__))
#define R_WEAK __attribute__ ((weak))
#else
#define R_UNUSED /* unused */
#define R_WEAK /* weak */
#endif

#if APPLE_SDK_IPHONESIMULATOR
#undef LIBC_HAVE_FORK
#define LIBC_HAVE_FORK 0
#undef DEBUGGER
#define DEBUGGER 0
#endif

#define HEAPTYPE(x) \
	static x* x##_new(x n) {\
		x *m = malloc(sizeof (x));\
		return m? *m = n, m: m; \
	}

#define R_DIRTY(x) (x)->is_dirty = true
#define R_IS_DIRTY(x) (x)->is_dirty
#define R_DIRTY_VAR bool is_dirty

#define R_TAG(x) (void*)((size_t)(x)|1)
#define R_UNTAG(x) (void*)((((size_t)(x))&(size_t)-2))
#define R_TAG_FREE(x) do { if (!((size_t)(x)&1)) { R_FREE(x); }} while(0)
#define R_TAG_NOP(x) untagged_pointer_check(x)
#define R_IS_TAGGED(x) ((size_t)(x)&1)
#define R_TAGGED
#if R_CHECKS_LEVEL == 0
static inline void *untagged_pointer_check(void *x) {
	return x;
}
#else
static inline void *untagged_pointer_check(void *x) {
	if (R_IS_TAGGED(x)) {
		int *p = (int*)0; *p = 0;
	}
	return x;
}
#endif

#define ALLOC_SIZE_LIMIT 0xffffff

#ifdef R_IPI
#undef R_IPI
#endif

#define R_IPI

#ifdef R_HEAP
#undef R_HEAP
#endif
#define R_HEAP

#ifdef R_API
#undef R_API
#endif
#if R_SWIG
  #define R_API export
#elif R_INLINE
  #define R_API inline
#else
  #if R2__WINDOWS__
    #define R_API __declspec(dllexport)
  #elif defined(__GNUC__) && __GNUC__ >= 4
    #define R_API __attribute__((visibility("default")))
  #else
    #define R_API
  #endif
#endif


#ifdef __cplusplus
}
#endif

#endif // R2_TYPES_BASE_H
