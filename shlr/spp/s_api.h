#ifndef S_STRBUF_H
#define S_STRBUF_H

#define R_FREE(x) { free(x); x = NULL; }
#define R_NEW0(x) (x*)calloc(1,sizeof(x))

#ifdef _MSC_VER
void do_printf(Output *out, char *str, ...);
#else
void do_printf(Output *out, char *str, ...) __attribute__ ((format (printf, 2, 3)));
#endif

SStrBuf *s_strbuf_new(const char *s);
bool s_strbuf_set(SStrBuf *sb, const char *s);
int s_strbuf_append(SStrBuf *sb, const char *s);
char *s_strbuf_get(SStrBuf *sb);
void s_strbuf_free(SStrBuf *sb);
void s_strbuf_fini(SStrBuf *sb);
void s_strbuf_init(SStrBuf *sb);
int s_sys_setenv(const char *key, const char *value);

#endif
