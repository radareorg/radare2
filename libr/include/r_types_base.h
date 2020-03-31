#ifndef R2_TYPES_BASE_H
#define R2_TYPES_BASE_H

#include <ctype.h>

#define cut8 const unsigned char
#define ut64 unsigned long long
#define st64 long long
#define ut32 unsigned int
#define st32 int
#define ut16 unsigned short
#define st16 short
#define ut8 unsigned char
#define st8 signed char
#define boolt int

#if defined(_MSC_VER)
# define R_ALIGNED(x) __declspec(align(x))
#else
# define R_ALIGNED(x) __attribute__((aligned(x)))
#endif

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
typedef struct _utX{
	ut80 v80;
	ut96 v96;
	ut128 v128;
	ut256 v256;
} utX;

#include <stdbool.h>

#define R_EMPTY { 0 }
#define R_EMPTY2 {{ 0 }}

/* limits */
#undef UT64_MAX
#undef UT64_GT0
#undef UT64_LT0
#undef UT64_MIN
#undef UT32_MAX
#undef UT32_MIN
#define ST64_MAX 0x7FFFFFFFFFFFFFFFULL
#define ST64_MIN (-ST64_MAX-1)
#define UT64_MAX 0xFFFFFFFFFFFFFFFFULL
#define UT64_GT0 0x8000000000000000ULL
#define UT64_LT0 0x7FFFFFFFFFFFFFFFULL
#define UT64_MIN 0ULL
#define UT64_32U 0xFFFFFFFF00000000ULL
#define UT64_16U 0xFFFFFFFFFFFF0000ULL
#define UT64_8U  0xFFFFFFFFFFFFFF00ULL
#define UT32_MIN 0U
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
#define ST8_MIN  (-ST8_MAX-1)
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU
#define UT8_MIN  0x00U

#define UT64_ALIGN(x) (x + (x - (x % sizeof (ut64))))
#define UT32_ALIGN(x) (x + (x - (x % sizeof (ut32))))
#define UT16_ALIGN(x) (x + (x - (x % sizeof (ut16))))

#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_HI(x) ((ut32)(((ut64)(x))>>32)&UT32_MAX)

/* preventive math overflow checks */
#if !defined(SZT_ADD_OVFCHK)
#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#endif
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define UT16_ADD_OVFCHK(x,y) ((UT16_MAX - (x)) < (y))
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))

/* copied from bithacks.h */
#define B_IS_SET(x, n)   (((x) & (1ULL<<(n)))?1:0)
#define B_SET(x, n)      ((x) |= (1ULL<<(n)))
#define B_EVEN(x)        (((x)&1)==0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_UNSET(x, n)    ((x) &= ~(1ULL<<(n)))
#define B_TOGGLE(x, n)   ((x) ^= (1ULL<<(n)))

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
#if !defined(INFINITY)
#define INFINITY (1.0f/0.0f)
#endif

#if !defined(NAN)
#define NAN (0.0f/0.0f)
#endif

#ifdef _MSC_VER
#define R_PACKED( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#undef INFINITY
#undef NAN
#elif defined(__GNUC__) || defined(__TINYC__)
#define R_PACKED( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

#if APPLE_SDK_IPHONESIMULATOR
#undef LIBC_HAVE_FORK
#define LIBC_HAVE_FORK 0
#undef DEBUGGER
#define DEBUGGER 0
#endif

#endif // R2_TYPES_BASE_H
