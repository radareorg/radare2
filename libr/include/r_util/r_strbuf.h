#ifndef R_STRBUF_H
#define R_STRBUF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char buf[32];
	size_t len; // string length in chars or binary buffer size
	char *ptr; // ptr replacing buf in case strlen > sizeof(buf)
	size_t ptrlen; // string length + 1 or binary buffer size
	bool weakref; // ptr is not owned
} RStrBuf;

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
R_API RStrBuf *r_strbuf_new(const char *s);
R_API const char *r_strbuf_set(RStrBuf *sb, const char *s); // return = the string or NULL on fail
R_API bool r_strbuf_slice(RStrBuf *sb, int from, int len);
R_API bool r_strbuf_setbin(RStrBuf *sb, const ut8 *s, size_t len);
R_API ut8* r_strbuf_getbin(RStrBuf *sb, int *len);
R_API const char *r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) R_PRINTF_CHECK(2, 3); // return = the string or NULL on fail
R_API const char *r_strbuf_vsetf(RStrBuf *sb, const char *fmt, va_list ap); // return = the string or NULL on fail
R_API bool r_strbuf_append(RStrBuf *sb, const char *s);
R_API bool r_strbuf_append_n(RStrBuf *sb, const char *s, size_t l);
R_API bool r_strbuf_prepend(RStrBuf *sb, const char *s);
R_API bool r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API bool r_strbuf_vappendf(RStrBuf *sb, const char *fmt, va_list ap);
R_API char *r_strbuf_get(RStrBuf *sb);
R_API char *r_strbuf_drain(RStrBuf *sb);
R_API char *r_strbuf_drain_nofree(RStrBuf *sb);
R_API int r_strbuf_length(RStrBuf *sb);
R_API int r_strbuf_size(RStrBuf *sb);
R_API void r_strbuf_free(RStrBuf *sb);
R_API void r_strbuf_fini(RStrBuf *sb);
R_API void r_strbuf_init(RStrBuf *sb);
R_API const char *r_strbuf_initf(RStrBuf *sb, const char *fmt, ...); // same as init + setf for convenience
R_API bool r_strbuf_copy(RStrBuf *dst, RStrBuf *src);
R_API bool r_strbuf_equals(RStrBuf *sa, RStrBuf *sb);
R_API bool r_strbuf_reserve(RStrBuf *sb, size_t len);
R_API bool r_strbuf_is_empty(RStrBuf *sb);
R_API bool r_strbuf_setptr(RStrBuf *sb, char *p, int l);

#ifdef __cplusplus
}
#endif

#endif //  R_STRBUF_H
