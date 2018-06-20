#if !HAVE_R_UTIL

#ifndef R_STRBUF_H
#define R_STRBUF_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef R_API
#undef R_API
#endif
#if R_SWIG
  #define R_API export
#elif R_INLINE
  #define R_API inline
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define R_API __attribute__((visibility("default")))
  #elif defined(_MSC_VER)
    #define R_API __declspec(dllexport)
  #else
    #define R_API
  #endif
#endif

#if defined(EMSCRIPTEN) || defined(__linux__) || defined(__APPLE__) || defined(__GNU__) || defined(__ANDROID__) || defined(__QNX__)
  #define __BSD__ 0
  #define __UNIX__ 1
#endif
#if __KFBSD__ || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
  #define __BSD__ 1
  #define __UNIX__ 1
#endif
#if __WIN32__ || __CYGWIN__ || MINGW32
  #define __addr_t_defined
  #include <windows.h>
#endif
#if __WIN32__ || MINGW32 && !__CYGWIN__
  #ifndef _MSC_VER
    #include <winsock.h>
  #endif
  typedef int socklen_t;
  #undef USE_SOCKETS
  #define __WINDOWS__ 1
  #undef __UNIX__
  #undef __BSD__
#endif

typedef struct {
	int len;
	char *ptr;
	int ptrlen;
	char buf[64];
} RStrBuf;

#define R_FREE(x) { free(x); x = NULL; }
#define R_NEW0(x) (x*)calloc(1,sizeof(x))

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
RStrBuf *r_strbuf_new(const char *s);
bool r_strbuf_set(RStrBuf *sb, const char *s);
int r_strbuf_append(RStrBuf *sb, const char *s);
char *r_strbuf_get(RStrBuf *sb);
void r_strbuf_free(RStrBuf *sb);
void r_strbuf_fini(RStrBuf *sb);
void r_strbuf_init(RStrBuf *sb);
#endif //  R_STRBUF_H

#endif // NO_UTIL
