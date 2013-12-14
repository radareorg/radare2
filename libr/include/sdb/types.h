#ifndef UINT32_H
#define UINT32_H

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef UNUSED
#ifdef __GNUC__
#define UNUSED	__attribute__((__unused__))
#else
#define UNUSED
#endif
#endif

#if __WIN32__ || __CYGWIN__ || MINGW32
#define WINDOWS 1
#else
#define WINDOWS 0
#endif

#ifndef ut8
#define ut8 unsigned char
#define ut32 unsigned int
#define ut64 unsigned long long
#define boolt int
#define R_NEW(x) (x*)malloc(sizeof(x))
#define R_ANEW(x) (x*)cdb_alloc(sizeof(x))
#define UT32_MAX ((ut32)0xffffffff)
#define UT64_MAX ((ut64)(0xffffffffffffffffLL))
#endif

#include "config.h"

#define SET 0 /* sigh */
#define CUR 1 /* sigh */
#define seek_cur(fd) (lseek((fd), 0, CUR))
#define seek_begin(fd) (seek_set ((fd), (off_t) 0))
static inline int seek_set(int fd, off_t pos) {
	return (fd==-1 || lseek (fd, (off_t) pos, SET) == -1)? 0:1;
}

#define byte_equal(s,n,t) (!byte_diff((s),(n),(t)))
#define byte_copy(d,l,s) memcpy(d,s,l)
#define byte_diff(d,l,s) memcmp(d,s,l)

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
