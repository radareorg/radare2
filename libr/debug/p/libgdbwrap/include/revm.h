#ifndef _INCLUDE_ERESI_H_
#define _INCLUDE_ERESI_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if 0
#define u_short unsigned short
#define u_char unsigned char
#define u_int unsigned int
#define uint8_t unsigned char
#endif

#define la32 unsigned int
#define ptrdiff_t int
#define ureg32 unsigned int
#define Bool int
#define QWORD_IN_BYTE 8
#define DWORD_IN_BYTE 4
#define BYTE_IN_BIT 8
#define BYTE_IN_CHAR 2
#define TRUE 1
#define FALSE 0
#define ASSERT(x) //
#define assert(x) //
#undef LOBYTE
#define LOBYTE(_w) ((_w) & 0xff)
#define NEXT_CHAR(_x) (_x+1)
#define PROFILER_IN(fd,fun,line) //
#define PROFILER_OUT(fd,fun,line,str,ret) //
#define PROFILER_ROUT(fd,fun,line,ret) return ret
#define PROFILER_ERR(fd,fun,line,str,ret) { fprintf(stderr, str"\n"); return ret; }

#endif
