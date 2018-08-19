#ifndef R_STRBUF_H
#define R_STRBUF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int len;
	char *ptr;
	int ptrlen;
	char buf[32];
} RStrBuf;

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
R_API RStrBuf *r_strbuf_new(const char *s);
R_API bool r_strbuf_set(RStrBuf *sb, const char *s);
R_API bool r_strbuf_setbin(RStrBuf *sb, const ut8 *s, int len);
R_API ut8* r_strbuf_getbin(RStrBuf *sb, int *len);
R_API bool r_strbuf_setf(RStrBuf *sb, const char *fmt, ...);
R_API int r_strbuf_append(RStrBuf *sb, const char *s);
R_API int r_strbuf_append_n(RStrBuf *sb, const char *s, int l);
R_API int r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...);
R_API char *r_strbuf_get(RStrBuf *sb);
R_API char *r_strbuf_drain(RStrBuf *sb);
R_API int r_strbuf_length(RStrBuf *sb);
R_API void r_strbuf_free(RStrBuf *sb);
R_API void r_strbuf_fini(RStrBuf *sb);
R_API void r_strbuf_init(RStrBuf *sb);
R_API bool r_strbuf_equals(RStrBuf *sa, RStrBuf *sb);

#ifdef __cplusplus
}
#endif

#endif //  R_STRBUF_H
