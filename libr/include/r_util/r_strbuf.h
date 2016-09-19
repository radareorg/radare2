#ifndef R_STRBUF_H
#define R_STRBUF_H

typedef struct {
	int len;
	char *ptr;
	int ptrlen;
	char buf[64];
} RStrBuf;

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
R_API RStrBuf *r_strbuf_new(const char *s);
R_API bool r_strbuf_set(RStrBuf *sb, const char *s);
R_API bool r_strbuf_setf(RStrBuf *sb, const char *fmt, ...);
R_API int r_strbuf_append(RStrBuf *sb, const char *s);
R_API int r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...);
R_API char *r_strbuf_get(RStrBuf *sb);
R_API char *r_strbuf_drain(RStrBuf *sb);
R_API void r_strbuf_free(RStrBuf *sb);
R_API void r_strbuf_fini(RStrBuf *sb);
R_API void r_strbuf_init(RStrBuf *sb);
#endif //  R_STRBUF_H
