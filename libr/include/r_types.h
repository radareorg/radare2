#ifndef _INCLUDE_R_TYPES_H_
#define _INCLUDE_R_TYPES_H_

/* provide a per-module debug-enabled feature */
#if R_DEBUG
#define IFDBG
#else
#define IFDBG if (0)
#endif

#if R_INLINE
#define R_API inline
#else
#define R_API
#endif

/* basic types */

#define u64 unsigned long long
#define s64 long long
#define u32 unsigned long
#define u16 unsigned short
#define u8  unsigned char

#define R_TRUE 1
#define R_FALSE 0

/* types */

#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#undef _GNU_SOURCE
#define _GNU_SOURCE

/* allocating */
#include <stdio.h>
#include <stdarg.h>
static inline int ERR(char *str, ...)
{
	va_list ap;
	va_start(ap, str);
	fprintf(stderr, str, ap);
	va_end(ap);
	return R_FALSE;
}
//#define ERR(...) fprintf(stderr, ...)
#define MALLOC_STRUCT(x) (x*)malloc(sizeof(x))
#define IS_PRINTABLE(x) (x>=' '&&x<='~')

/* operating system */

#undef __BSD__
#undef __UNIX__
#undef __WINDOWS__

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #define __BSD__ 1
#endif

#if __WIN32__ || __CYGWIN__ || MINGW32
  #define __addr_t_defined
  #include <windows.h>
  #ifdef USE_SOCKETS
  #include <winsock.h>
  #undef USE_SOCKETS
#endif

  #define __WINDOWS__ 1
#else
  #define __UNIX__ 1
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if __UNIX__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif
#include <unistd.h>

/* Move outside */
#define _perror(str,file,line) \
  { char buf[128];sprintf(buf, "%s:%d %s", file,line,str);perror(buf); }
#define perror(x) _perror(x,__FILE__,__LINE__)

#define eprintf(x,y...) fprintf(stderr,x,##y)

/* limits */
#define U64_MAX 0xFFFFFFFFFFFFFFFFLL
#define U64_GT0 0x8000000000000000LL
#define U64_LT0 0x7FFFFFFFFFFFFFFFLL
#define U64_MIN 0LL
#define U64_32U 0xFFFFFFFF00000000LL
#define U32_MIN 0
#define U32_GT0 0x80000000
#define U32_LT0 0x7FFFFFFF
#define U32_MAX 0xFFFFFFFF

#define R_MAX(x,y) (x>y)?x:y
#define R_MIN(x,y) (x>y)?y:x
#define R_ABS(x) ((x<0)?-x:x)

#define R_FALSE 0
#define R_TRUE 1

#define R_FREE(x) { free(x); x=NULL; }

#if 0
#define R_API_NEW(x) \
  struct x##_t *##x##_new() \
  { struct x##_t *t = (struct x##_t)malloc(sizeof(struct x##_t)); \
   x##_init(t); return t; }
R_API_NEW(r_trace);
#endif

#endif
