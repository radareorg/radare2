#ifndef _INCLUDE_R_TYPES_BASE_H_
#define _INCLUDE_R_TYPES_BASE_H_

#define ut64 unsigned long long
#define st64 long long
#define ut32 unsigned int
#define st32 int
#define ut16 unsigned short
#define ut8  unsigned char
#define st8  char

#define R_FAIL -1
#define R_FALSE 0
#define R_TRUE 1
#define R_TRUFAE 2

/* limits */
#define UT64_MAX 0xFFFFFFFFFFFFFFFFLL
#define UT64_GT0 0x8000000000000000LL
#define UT64_LT0 0x7FFFFFFFFFFFFFFFLL
#define UT64_MIN 0LL
#define UT64_32U 0xFFFFFFFF00000000LL
#define UT32_MIN 0
#define UT32_GT0 0x80000000
#define UT32_LT0 0x7FFFFFFF
#define ST32_MAX 0x7FFFFFFF
#define UT32_MAX 0xFFFFFFFF

#endif
