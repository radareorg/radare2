#ifndef _INCLUDE_R_TYPES_H_
#define _INCLUDE_R_TYPES_H_

/* provide a per-module debug-enabled feature */
#if DEBUG_ENABLED
#define IFDBG
#else
#define IFDBG //
#endif

/* basic types */

#define u64 unsigned long long
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
//#define eprintf(...) fprintf(stderr, ...)
#define MALLOC_STRUCT(x) (x*)malloc(sizeof(x))

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

#endif
