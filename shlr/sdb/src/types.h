#ifndef TYPES_H
#define TYPES_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#undef eprintf
#define eprintf(...) fprintf(stderr,__VA_ARGS__)

// Copied from https://gcc.gnu.org/wiki/Visibility
#ifndef SDB_API
	#undef SDB_IPI
	#if defined _WIN32 || defined __CYGWIN__
		#ifdef __GNUC__
			#define SDB_API __attribute__ ((dllexport))
		#else
			#define SDB_API __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
		#endif
		#define SDB_IPI
	#else
	#if __GNUC__ >= 4
		#define SDB_API __attribute__ ((visibility ("default")))
		#define SDB_IPI  __attribute__ ((visibility ("hidden")))
	#else
		#define SDB_API
		#define SDB_IPI
	#endif
	#endif
#endif

#if MINGW || __MINGW32__ || __MINGW64__
#define __MINGW__ 1
#endif

#if __WIN32__ || __MINGW__ || __WINDOWS__ || _MSC_VER
#define __SDB_WINDOWS__ 1
#define DIRSEP '\\'
#include <windows.h>
#include <io.h>
#else
// CYGWIN AND UNIX
#define __SDB_WINDOWS__ 0
#define DIRSEP '/'
#include <unistd.h>
#endif

#include <inttypes.h>
#if __SDB_WINDOWS__ && !__CYGWIN__
#define HAVE_MMAN 0
#define ULLFMT "I64"
#else
#define HAVE_MMAN 1
#define ULLFMT "ll"
#endif

#ifndef USE_MMAN
#define USE_MMAN HAVE_MMAN
#endif

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
#ifndef R_NEW
//it means we are within sdb
#define R_NEW(x) (x*)malloc(sizeof(x))
#endif
#ifndef R_NEW0
#define R_NEW0(x) (x*)calloc(1, sizeof(x))
#endif
#ifndef R_FREE
#define R_FREE(x) { free (x); x = NULL; }
#endif
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
	return ((fd == -1) || (lseek (fd, (off_t) pos, SEEK_SET) == -1))? 0:1;
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
