/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdlib.h>

#if 0
 buf       |__________________________________|
 bufptr[]  ^     ^        ^  ^       ^
 bufidx  >---------------------------/
#endif

/* 256 chunks with 30 KB */
#define ALLOC_SIZE 1024*30
#define ALLOC_BLKS 256

static ut8 *buf = NULL;
static ut8 *bufptr[ALLOC_BLKS];
static int bufidx = 0;
static ut8 *bufnext = 0;
static ut8 *bufmax;

R_API int r_alloca_init() {
	buf = (ut8 *)malloc(ALLOC_SIZE);
	if (buf == NULL)
		return R_FALSE;
	bufptr[0] = buf;
	bufnext = buf;
	bufmax = buf + ALLOC_SIZE;
	return R_TRUE;
}

R_API ut8 *r_alloca_bytes(int len) {
	ut8 *next = bufnext;
	ut8 *tnext = bufnext + len;
	if (tnext > bufmax)
		return NULL;
	bufnext = bufptr[++bufidx] = tnext;
	return next;
}

R_API char *r_alloca_str(const char *str) {
	int len;
	ut8 *p;
	if (str == NULL) {
		len = 1;
		p = r_alloca_bytes(1);
		if (p != NULL) *p='\0';
	} else {
		len = strlen(str)+1;
		p = r_alloca_bytes(len);
		if (p != NULL)
			memcpy(p, str, len);
	}
	return (char *)p;
}

/* free last allocated buffer */
R_API int r_alloca_ret_i(int n) {
	/* check for underflows */
	if (bufidx==0) return n;
	bufnext = bufptr[--bufidx];
	return n;
}
