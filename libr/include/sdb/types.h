#ifndef TYPES_H
#define TYPES_H

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#undef eprintf
#define eprintf(x,y...) fprintf(stderr,x,##y)

#ifndef SDB_API
#if defined(__GNUC__)
#define SDB_API __attribute__((visibility("default")))
#else
#define SDB_API
#endif
#endif

#if MINGW || __MINGW32__ || __MINGW64__
#define __MINGW__ 1
#endif

#if __CYGWIN__
#define ULLFMT "ll"
#define USE_MMAN 1
#elif __WIN32__ || __MINGW__
#define ULLFMT "I64"
#define USE_MMAN 0
#else
#define ULLFMT "ll"
#define USE_MMAN 1
#endif

#if __WIN32__ || __CYGWIN__ || __MINGW__
#undef __WINDOWS__
#define __WINDOWS__ 1
#include <windows.h>
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

#ifndef UNUSED
#ifdef __GNUC__
#define UNUSED	__attribute__((__unused__))
#else
#define UNUSED
#endif
#endif

#if __WIN32__ || __CYGWIN__ || __MINGW32__
#define WINDOWS 1
#else
#define WINDOWS 0
#endif

#ifndef ut8
#define ut8 unsigned char
#define ut32 unsigned int
#define ut64 unsigned long long
#define boolt int
// TODO: deprecate R_NEW
#define R_NEW(x) (x*)malloc(sizeof(x))
#define R_NEW0(x) (x*)calloc(1,sizeof(x))
#define R_ANEW(x) (x*)cdb_alloc(sizeof(x))
#define UT32_MAX ((ut32)0xffffffff)
#define UT64_MAX ((ut64)(0xffffffffffffffffLL))
#endif

#include "config.h"

static inline int seek_set(int fd, off_t pos) {
	return (fd==-1 || lseek (fd, (off_t) pos, SEEK_SET) == -1)? 0:1;
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
	ut32 result;
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
