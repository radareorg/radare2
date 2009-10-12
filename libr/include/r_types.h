#ifndef _INCLUDE_R_TYPES_H_
#define _INCLUDE_R_TYPES_H_

#include <r_userconf.h>

/* provide a per-module debug-enabled feature */
#if R_DEBUG
#define IFDBG
#else
#define IFDBG if (0)
#endif

#if R_RTDEBUG
#define IFRTDBG if (getenv("LIBR_DEBUG"))
#else
#define IFRTDBG if (0)
#endif
/* ------------------------------------------- */

#if R_INLINE
#define R_API inline
#else
#define R_API
#endif

// Usage: R_DEFINE_OBJECT(r_asm);
#if 0
#define R_DEFINE_OBJECT(type) \
 R_API struct type##_t* type##_new() { \
    return type##_init(MALLOC_STRUCT(struct type##_t)); \
 } \
 R_API struct type##_t* type##_free(struct type##_t *foo) { \
    return (type##_deinit(foo), free(foo), NULL); \
 }
#endif

/* basic types */

#define BITS2BYTES(x) ((x/8)+((x%8)?1:0))

#define ut64 unsigned long long
#define st64 long long
#define ut32 unsigned int
#define ut16 unsigned short
#define ut8  unsigned char

#define R_TRUE 1
#define R_FALSE 0

/* types */

#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#undef _GNU_SOURCE
#define _GNU_SOURCE
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE

/* allocating */
#include <stdio.h>
#include <stdarg.h>
static inline int ERR(char *str, ...)
{
	va_list ap;
	va_start(ap, str);
	vfprintf(stderr, str, ap);
	va_end(ap);
	return R_FALSE;
}
//#define ERR(...) fprintf(stderr, ...)
#define MALLOC_STRUCTS(x,y) (x*)malloc(sizeof(x)*y)
#define MALLOC_STRUCT(x) (x*)malloc(sizeof(x))
#define IS_PRINTABLE(x) (x>=' '&&x<='~')
#define IS_WHITESPACE(x) (x==' '||x=='\t')

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
#define UT64_MAX 0xFFFFFFFFFFFFFFFFLL
#define UT64_GT0 0x8000000000000000LL
#define UT64_LT0 0x7FFFFFFFFFFFFFFFLL
#define UT64_MIN 0LL
#define UT64_32U 0xFFFFFFFF00000000LL
#define UT32_MIN 0
#define UT32_GT0 0x80000000
#define UT32_LT0 0x7FFFFFFF
#define UT32_MAX 0xFFFFFFFF

#define R_MAX(x,y) (x>y)?x:y
#define R_MIN(x,y) (x>y)?y:x
#define R_ABS(x) ((x<0)?-x:x)

#define R_FAIL -1
#define R_FALSE 0
#define R_TRUE 1
#define R_TRUFAE 2

#define R_FREE(x) { free(x); x = NULL; }

#if __WINDOWS__
#define HAVE_REGEXP 0
#else
#define HAVE_REGEXP 1
#endif

/* hacks for vala-list.h interaction */
#define list_entry_vala(pos, type, member) ((type)((char*)pos-(unsigned long)(&((type)0)->member)))
#define ralist_iterator(x) x->next
#define ralist_get(x,y) list_entry_vala(x, y, list); x=x->next
#define ralist_next(x) (x=x->next, (x != head))
#define ralist_free(x) (x)

#if 1
#define rarray_get(x,y) x; x=((y)x)+1;
#define rarray_next(x,y) (( ((y)x)->last ) ?free(x),x=0,0:1)
#define rarray_iterator(x) x
#define rarray_free(x) x
//free(x)
#else
typedef struct { void* head; void *cur; } rarray_t;
#define rarray_get(x,y) (x)->cur; (x)->cur=((y)(x)->cur)+1
#define rarray_next(x,y) !((y)(x)->cur)->last
#define rarray_iterator(x,y) (y)->cur=(x),(y)->head=(y)->cur,*(y)
//{.cur=(void*)x,.head=(void*)x}
#define rarray_free(x) (free((x)->head))
#endif

#endif
