/* radare - LGPL - Copyright 2013 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

R_API RStrBuf *r_strbuf_new() {
	return R_NEW0 (RStrBuf);
}

R_API void r_strbuf_init(RStrBuf *sb) {
	memset (sb, 0, sizeof (RStrBuf));
}

R_API void r_strbuf_set(RStrBuf *sb, const char *s) {
	int l = strlen (s);
	if (l>=sizeof (sb->buf)) {
		free (sb->ptr);
		sb->ptr = malloc (l+1);
		memcpy (sb->ptr, s, l+1);
	} else {
		sb->ptr = NULL;
		memcpy (sb->buf, s, l+1);
	}
	sb->len = l;
}

R_API void r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) {
	int ret;
	char string[4096];
	va_list ap;

	va_start (ap, fmt);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret>=sizeof (string)) {
		char *p = malloc (ret+2);
		if (!p) return;
		vsnprintf (p, ret+1, fmt, ap);
		r_strbuf_set (sb, p);
		free (p);
	} else r_strbuf_set (sb, string);
	va_end (ap);
}

R_API void r_strbuf_append(RStrBuf *sb, const char *s) {
	int l = strlen (s);
	if ((sb->len+l+1)<sizeof (sb->buf)) {
		strcpy (sb->buf+sb->len, s);
		sb->ptr = NULL;
	} else {
		char *p = malloc (sb->len+l+1);
		strcpy (p, sb->ptr?sb->ptr:sb->buf);
		strcpy (p+sb->len, s);
		free (sb->ptr);
		sb->ptr = p;
	}
	sb->len += l;
}

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
