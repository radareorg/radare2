/*
    Portable header to provide the 32 and 64 bits type.

    Not a compatible replacement for <stdint.h>, do not blindly use it as such.
*/

#if ((defined(__STDC__) && __STDC__ && __STDC_VERSION__ >= 199901L) || (defined(__WATCOMC__) && (defined(_STDINT_H_INCLUDED) || __WATCOMC__ >= 1250)) || (defined(__GNUC__) && (defined(_STDINT_H) || defined(_STDINT_H_) || defined(__UINT_FAST64_TYPE__)))) && !defined(FIXEDINT_H_INCLUDED)
#include <stdint.h>
#define FIXEDINT_H_INCLUDED

#if defined(__WATCOMC__) && __WATCOMC__ >= 1250 && !defined(UINT64_C)
#include <limits.h>
#define UINT64_C(x) (x + (UINT64_MAX - UINT64_MAX))
#endif
#endif

#ifndef FIXEDINT_H_INCLUDED
#define FIXEDINT_H_INCLUDED

#include <limits.h>

/* (u)int32_t */
#ifndef uint32_t
#if (ULONG_MAX == 0xffffffffUL)
typedef unsigned long uint32_t;
#elif (UINT_MAX == 0xffffffffUL)
typedef unsigned int uint32_t;
#elif (USHRT_MAX == 0xffffffffUL)
typedef unsigned short uint32_t;
#endif
#endif

#ifndef int32_t
#if (LONG_MAX == 0x7fffffffL)
typedef signed long int32_t;
#elif (INT_MAX == 0x7fffffffL)
typedef signed int int32_t;
#elif (SHRT_MAX == 0x7fffffffL)
typedef signed short int32_t;
#endif
#endif

/* (u)int64_t */
#if (defined(__STDC__) && defined(__STDC_VERSION__) && __STDC__ && __STDC_VERSION__ >= 199901L)
typedef long long int64_t;
typedef unsigned long long uint64_t;

#define UINT64_C(v) v##ULL
#define INT64_C(v)  v##LL
#elif defined(__GNUC__)
__extension__ typedef long long int64_t;
__extension__ typedef unsigned long long uint64_t;

#define UINT64_C(v) v##ULL
#define INT64_C(v)  v##LL
#elif defined(__MWERKS__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC) || defined(__APPLE_CC__) || defined(_LONG_LONG) || defined(_CRAYC)
typedef long long int64_t;
typedef unsigned long long uint64_t;

#define UINT64_C(v) v##ULL
#define INT64_C(v)  v##LL
#elif (defined(__WATCOMC__) && defined(__WATCOM_INT64__)) || (defined(_MSC_VER) && _INTEGRAL_MAX_BITS >= 64) || (defined(__BORLANDC__) && __BORLANDC__ > 0x460) || defined(__alpha) || defined(__DECC)
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#define UINT64_C(v) v##UI64
#define INT64_C(v)  v##I64
#endif
#endif
