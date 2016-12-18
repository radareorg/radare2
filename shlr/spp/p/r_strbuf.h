#if NO_UTIL

#ifndef R_STRBUF_H
#define R_STRBUF_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

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