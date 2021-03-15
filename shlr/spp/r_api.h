#ifndef S_STRBUF_H
#define S_STRBUF_H

#ifndef R_FREE
#define R_FREE(x) { free(x); x = NULL; }
#endif
#ifndef R_NEW0
#define R_NEW0(x) (x*)calloc(1,sizeof(x))
#endif

#ifdef _MSC_VER
void out_printf(Output *out, char *str, ...);
#else
void out_printf(Output *out, char *str, ...) __attribute__ ((format (printf, 2, 3)));
#endif

#if USE_R2
#include <r_util.h>
#else
SStrBuf *r_strbuf_new(const char *s);
bool r_strbuf_set(SStrBuf *sb, const char *s);
bool r_strbuf_append(SStrBuf *sb, const char *s);
char *r_strbuf_get(SStrBuf *sb);
char *r_strbuf_drain(SStrBuf *sb);
void r_strbuf_free(SStrBuf *sb);
void r_strbuf_fini(SStrBuf *sb);
void r_strbuf_init(SStrBuf *sb);
int r_sys_setenv(const char *key, const char *value);
char *r_sys_getenv(const char *key);
int r_sys_getpid(void);
#endif

#endif
