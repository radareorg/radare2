#ifndef _INCLUDE_R_TYPES_BASE_H_
#define _INCLUDE_R_TYPES_BASE_H_

#define ut64 unsigned long long
#define st64 long long
#define ut32 unsigned int
#define st32 int
#define ut16 unsigned short
#define ut8  unsigned char
#define st8  char
/* TODO: choose */
#define bt1  int
#define boolt int

#define R_FAIL -1
#define R_FALSE 0
#define R_TRUE 1
#define R_TRUFAE 2

/* limits */
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
#define UT16_GT0 0x8000U
#define UT16_MAX 0xFFFFU
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU

/* copied from bithacks.h */
#define B_IS_SET(x, n)   (((x) & (1<<(n)))?1:0)
#define B_SET(x, n)      ((x) |= (1<<(n)))
#define B_EVEN(x)        (((x)&1)==0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_UNSET(x, n)    ((x) &= ~(1<<(n)))
#define B_TOGGLE(x, n)   ((x) ^= (1<<(n)))

#endif
