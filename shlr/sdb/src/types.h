#ifndef TYPES_H
#define TYPES_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#undef eprintf
#define eprintf(x,y...) fprintf(stderr,x,##y)

#ifndef SDB_API
#if defined(__GNUC__) && __GNUC__ >= 4
#define SDB_API __attribute__((visibility("default")))
#else
#define SDB_API
#endif
#endif

#if MINGW || __MINGW32__ || __MINGW64__
#define __MINGW__ 1
#endif

#if __WIN32__ || __MINGW__ || __WINDOWS__
#define __SDB_WINDOWS__ 1
#include <windows.h>
#define DIRSEP '\\'
#else
// CYGWIN AND UNIX
#define __SDB_WINDOWS__ 0
#define DIRSEP '/'
#endif

#include <inttypes.h>
#if __CYGWIN__
#define USE_MMAN 1
#define ULLFMT "ll"
#elif __SDB_WINDOWS__
#define USE_MMAN 0
#define ULLFMT "I64"
#else
#define ULLFMT "ll"
#define USE_MMAN 1
#endif

#include <unistd.h>

#ifndef UNUSED
#  define UNUSED
#  ifdef __GNUC__
#    if __GNUC__ >= 4
#      undef UNUSED
#      define UNUSED __attribute__((__unused__))
#    endif
#  endif
#endif

#ifndef ut8
#define ut8 unsigned char
#define ut32 unsigned int
#define ut64 unsigned long long
#define st64 long long
#define boolt int
// TODO: deprecate R_NEW
#define R_NEW(x) (x*)malloc(sizeof(x))
#define R_NEW0(x) (x*)calloc(1,sizeof(x))
#define UT32_MAX ((ut32)0xffffffff)
#define UT64_MAX ((ut64)(0xffffffffffffffffLL))
#endif
#ifndef R_MAX_DEFINED
#define R_MAX(x,y) (((x)>(y))?(x):(y))
#define R_MAX_DEFINED 1
#endif

#ifndef R_MIN_DEFINED
#define R_MIN(x,y) (((x)>(y))?(y):(x))
#define R_MIN_DEFINED 1
#endif

#include "config.h"

static inline int seek_set(int fd, off_t pos) {
	return ((fd==-1) || (lseek (fd, (off_t) pos, SEEK_SET) == -1))? 0:1;
}

static inline void ut32_pack(char s[4], ut32 u) {
	s[0] = u & 255;
	u >>= 8;
	s[1] = u & 255;
	u >>= 8;
	s[2] = u & 255;
	s[3] = u >> 8;
}

static inline void ut32_pack_big(char s[4], ut32 u) {
	s[3] = u & 255;
	u >>= 8;
	s[2] = u & 255;
	u >>= 8;
	s[1] = u & 255;
	s[0] = u >> 8;
}

static inline void ut32_unpack(char s[4], ut32 *u) {
	ut32 result = 0;
	result = (ut8) s[3];
	result <<= 8;
	result += (ut8) s[2];
	result <<= 8;
	result += (ut8) s[1];
	result <<= 8;
	result += (ut8) s[0];
	*u = result;
}

#endif
