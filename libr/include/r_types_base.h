#ifndef R2_TYPES_BASE_H
#define R2_TYPES_BASE_H

#include <ctype.h>

#define ut64 unsigned long long
#define st64 long long
#define ut32 unsigned int
#define st32 int
#define ut16 unsigned short
#define st16 short
#define ut8 unsigned char
#define st8 char
#define boolt int

#define R_ERROR -2
#define R_FAIL -1
#define R_FALSE 0
#define R_TRUE 1
#define R_TRUFAE 2
#define R_NOTNULL (void*)(size_t)1

/* limits */
#undef UT64_MAX
#undef UT64_GT0
#undef UT64_LT0
#undef UT64_MIN
#undef UT32_MAX
#undef UT32_MIN
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
#define UT32_MAX 0xFFFFFFFFU
#define UT32_MIN 0U
#define UT16_GT0 0x8000U
#define UT16_MAX 0xFFFFU
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU
#define UT8_MIN  0x00U

#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_HI(x) ((ut32)(((ut64)(x))>>32)&UT32_MAX)

/* copied from bithacks.h */
#define B_IS_SET(x, n)   (((x) & (1<<(n)))?1:0)
#define B_SET(x, n)      ((x) |= (1<<(n)))
#define B_EVEN(x)        (((x)&1)==0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_UNSET(x, n)    ((x) &= ~(1<<(n)))
#define B_TOGGLE(x, n)   ((x) ^= (1<<(n)))

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
#undef B
#define B4(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))

#endif
