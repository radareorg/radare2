/* radare - LGPL - Copyright 2013-2014 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

R_API RStrBuf *r_strbuf_new(const char *str) {
	RStrBuf *s = R_NEW0 (RStrBuf);
	if (str) r_strbuf_set (s, str);
	return s;
}

R_API void r_strbuf_init(RStrBuf *sb) {
	memset (sb, 0, sizeof (RStrBuf));
}

R_API int r_strbuf_set(RStrBuf *sb, const char *s) {
	int l;
	if (!sb || !s) return R_FALSE;
	l = strlen (s);
	if (l>=sizeof (sb->buf)) {
		char *ptr = malloc (l+1);
		if (!ptr)
			return R_FALSE;
		free (sb->ptr);
		sb->ptr = ptr;
		memcpy (ptr, s, l+1);
	} else {
		sb->ptr = NULL;
		memcpy (sb->buf, s, l+1);
	}
	sb->len = l;
	return R_TRUE;
}

R_API int r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) {
	int ret;
	char string[4096];
	va_list ap;

	va_start (ap, fmt);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret>=sizeof (string)) {
		char *p = malloc (ret+2);
		if (!p) {
			va_end (ap);
			return R_FALSE;
		}
		vsnprintf (p, ret+1, fmt, ap);
		ret = r_strbuf_set (sb, p);
		free (p);
	} else ret = r_strbuf_set (sb, string);
	va_end (ap);
	return ret;
}

R_API int r_strbuf_append(RStrBuf *sb, const char *s) {
	int l = strlen (s)+1;
	if ((sb->len+l+1)<sizeof (sb->buf)) {
		memcpy (sb->buf+sb->len, s, l);
		sb->ptr = NULL;
	} else {
		char *d, *p;
		d = sb->ptr?sb->ptr:sb->buf;
		p = malloc (sb->len+l);
		if (!p) return R_FALSE;
		memcpy (p, d, sb->len);
		memcpy (p+sb->len, s, l);
		free (sb->ptr);
		sb->ptr = p;
	}
	sb->len += l;
	return R_TRUE;
}

R_API int r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...) {
	int ret;
	char string[4096];
	va_list ap;

	va_start (ap, fmt);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret>=sizeof (string)) {
		char *p = malloc (ret+2);
		if (!p) {
			va_end (ap);
			return R_FALSE;
		}
		vsnprintf (p, ret+1, fmt, ap);
		ret = r_strbuf_append (sb, p);
		free (p);
	} else ret = r_strbuf_append (sb, string);
	va_end (ap);
	return ret;
}

// TODO: rename to tostring()
R_API char *r_strbuf_get(RStrBuf *sb) {
	if (sb) {
		if (sb->ptr)
			return sb->ptr;
		return sb->buf;
	}
	return NULL;
}

R_API void r_strbuf_free(RStrBuf *sb) {
	r_strbuf_fini (sb);
	free (sb);
}

R_API void r_strbuf_fini(RStrBuf *sb) {
	if (sb && sb->ptr)
		free (sb->ptr);
}
