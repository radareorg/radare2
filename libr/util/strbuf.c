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

R_API bool r_strbuf_set(RStrBuf *sb, const char *s) {
	int l;
	if (!sb) {
		return false;
	}
	if (!s) {
		r_strbuf_init (sb);
		return true;
	}
	l = strlen (s);
	if (l >= sizeof (sb->buf)) {
		char *ptr = sb->ptr;
		if (!ptr || l+1 > sb->ptrlen) {
			ptr = malloc (l + 1);
			if (!ptr) {
				return false;
			}
			sb->ptrlen = l + 1;
			sb->ptr = ptr;
		}
		memcpy (ptr, s, l+1);
	} else {
		sb->ptr = NULL;
		memcpy (sb->buf, s, l+1);
	}
	sb->len = l;
	return true;
}

R_API bool r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) {
	int rc;
	bool ret;
	char string[1024];
	va_list ap, ap2;

	if (!sb || !fmt)
		return false;
	va_start (ap, fmt);
	va_copy (ap2, ap);
	rc = vsnprintf (string, sizeof (string), fmt, ap);
	if (rc >= sizeof (string)) {
		char *p = malloc (rc + 1);
		if (!p) {
			ret = false;
			goto done;
		}
		vsnprintf (p, rc + 1, fmt, ap2);
		ret = r_strbuf_set (sb, p);
		free (p);
	} else {
		ret = r_strbuf_set (sb, string);
	}
done:
	va_end (ap2);
	va_end (ap);
	return ret;
}

R_API int r_strbuf_append(RStrBuf *sb, const char *s) {
	int l = strlen (s);
	return r_strbuf_append_n (sb, s, l);
}

R_API int r_strbuf_append_n(RStrBuf *sb, const char *s, int l) {
	if (l < 1) {
		return false;
	}
	if ((sb->len + l + 1) <= sizeof (sb->buf)) {
		memcpy (sb->buf + sb->len, s, l + 1);
		R_FREE (sb->ptr);
	} else {
		int newlen = sb->len + l + 128;
		char *p = sb->ptr;
		bool allocated = true;
		if (!sb->ptr) {
			p = malloc (newlen);
			if (p && sb->len > 0) {
				memcpy (p, sb->buf, sb->len);
			}
		} else if (sb->len + l + 1 > sb->ptrlen) {
			p = realloc (sb->ptr, newlen);
		} else {
			allocated = false;
		}
		if (allocated) {
			if (!p) return false;
			sb->ptr = p;
			sb->ptrlen = newlen;
		}
		memcpy (p + sb->len, s, l + 1);
	}
	sb->len += l;
	return true;
}

R_API int r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...) {
	int ret;
	char string[1024];
	va_list ap;

	va_start (ap, fmt);
	ret = vsnprintf (string, sizeof (string) - 1, fmt, ap);
	if (ret >= sizeof (string)) {
		char *p = malloc (ret + 2);
		if (!p) {
			va_end (ap);
			return false;
		}
		*p = 0;
		va_start (ap, fmt);
		(void)vsnprintf (p, ret, fmt, ap);
		ret = r_strbuf_append (sb, p);
		free (p);
	} else {
		string[ret] = 0;
		ret = r_strbuf_append (sb, string);
	}
	va_end (ap);
	return ret;
}

R_API char *r_strbuf_get(RStrBuf *sb) {
	return sb? (sb->ptr? sb->ptr: sb->buf) : NULL;
}

R_API char *r_strbuf_drain(RStrBuf *sb) {
	char *ret = NULL;
	if (sb) {
		ret = sb->ptr? sb->ptr: strdup (sb->buf);
		free (sb);
	}
	return ret;
}

R_API void r_strbuf_free(RStrBuf *sb) {
	r_strbuf_fini (sb);
	free (sb);
}

R_API void r_strbuf_fini(RStrBuf *sb) {
	if (sb && sb->ptr)
		R_FREE (sb->ptr);
}
