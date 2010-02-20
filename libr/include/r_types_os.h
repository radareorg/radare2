#ifndef _INCLUDE_R_TYPES_OS_H_
#define _INCLUDE_R_TYPES_OS_H_

/* types */
#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#undef _GNU_SOURCE
#define _GNU_SOURCE
// do we really need those undefs?
//#undef _XOPEN_SOURCE
//#define _XOPEN_SOURCE
//#undef _POSIX_C_SOURCE
//#define _POSIX_C_SOURCE

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
#include <sys/time.h>
#if __UNIX__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif
#include <unistd.h>

#endif
