/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdlib.h>

#if 0
 buf       |__________________________________|
 bufptr[]  ^     ^        ^  ^       ^
 bufidx  >---------------------------'
#endif

/* 256 chunks with 30 KB */
#define ALLOC_SIZE 1024*30
#define ALLOC_BLKS 256

static u8 *buf = NULL;
static u8 *bufptr[ALLOC_BLKS];
static int bufidx = 0;
static u8 *bufnext = 0;
static u8 *bufmax;

int r_alloca_init()
{
	buf = (u8 *)malloc(ALLOC_SIZE);
	if (buf == NULL)
		return R_FALSE;
	bufptr[0] = buf;
	bufnext = buf;
	bufmax = buf + ALLOC_SIZE;
	return R_TRUE;
}

char *r_alloca_bytes(int len)
{
	u8 *next = bufnext;
	u8 *tnext = bufnext + len;
	if (tnext > bufmax)
		return NULL;
	bufnext = bufptr[++bufidx] = tnext;
	return next;
}

char *r_alloca_str(const char *str)
{
	int len;
	char *p;
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
	return p;
}

/* free last allocated buffer */
int r_alloca_ret_i(int n)
{
	/* check for underflows */
	if (bufidx==0) return n;
	bufnext = bufptr[--bufidx];
	return n;
}
