#ifndef SDB_TYPES_H
#define SDB_TYPES_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#undef eprintf
#define eprintf(...) fprintf(stderr,__VA_ARGS__)

// Inspired in https://gcc.gnu.org/wiki/Visibility
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

#ifndef INT32_MAX
#define INT32_MAX (0x7fffffff)
#endif

#if defined __WIN32__ || __MINGW__ > 0 || R2__WINDOWS__ || __WINDOWS__ > 0 || _MSC_VER > 0
#define __SDB_WINDOWS__ 1
#undef DIRSEP
#define DIRSEP '\\'
#undef lseek
#define lseek _lseek
#include <windows.h>
#include <io.h>
#if __MINGW32__
#define ULLFMT PRIx64
#else
#define ULLFMT "I64"
#endif
#undef HAVE_MMAN
#define HAVE_MMAN 0
#else
// CYGWIN AND UNIX
#define __SDB_WINDOWS__ 0
#undef DIRSEP
#define DIRSEP '/'
#include <unistd.h>
#undef HAVE_MMAN
#define HAVE_MMAN 1
#define ULLFMT PRIx64
#endif

#if __wasi__ || EMSCRIPTEN
#undef HAVE_MMAN
#define HAVE_MMAN 0
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
#define ut8 uint8_t
#define ut32 uint32_t
#define ut64 uint64_t
#define st64 int64_t

// TODO: deprecate R_NEW
#ifndef R_NEW
//it means we are within sdb
#define R_NEW(x) (x*)sdb_gh_malloc(sizeof(x))
#endif
#ifndef R_NEW0
#define R_NEW0(x) (x*)sdb_gh_calloc(1, sizeof(x))
#endif
#ifndef R_FREE
#define R_FREE(x) { sdb_gh_free (x); x = NULL; }
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

SDB_API char *sdb_strdup(const char *s);

#ifdef __cplusplus
}
#endif

#endif
