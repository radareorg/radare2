/* radare - LGPL - Copyright 2013-2020 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

R_API RStrBuf *r_strbuf_new(const char *str) {
	RStrBuf *s = R_NEW0 (RStrBuf);
	if (str) {
		r_strbuf_set (s, str);
	}
	return s;
}

R_API bool r_strbuf_equals(RStrBuf *sa, RStrBuf *sb) {
	r_return_val_if_fail (sa && sb, false);
	if (sa->len != sb->len) {
		return false;
	}
	return strcmp (r_strbuf_get (sa), r_strbuf_get (sb)) == 0;
}

R_API bool r_strbuf_is_empty(RStrBuf *sb) {
	return sb->len == 0;
}

R_API int r_strbuf_length(RStrBuf *sb) {
	r_return_val_if_fail (sb, 0);
	return sb->len;
}

R_API void r_strbuf_init(RStrBuf *sb) {
	r_return_if_fail (sb);
	memset (sb, 0, sizeof (RStrBuf));
}

R_API const char *r_strbuf_initf(RStrBuf *sb, const char *fmt, ...) {
	r_return_val_if_fail (sb && fmt, NULL);
	r_strbuf_init (sb);
	va_list ap;
	va_start (ap, fmt);
	const char *r = r_strbuf_vsetf (sb, fmt, ap);
	va_end (ap);
	return r;
}

R_API bool r_strbuf_copy(RStrBuf *dst, RStrBuf *src) {
	r_return_val_if_fail (dst && src, false);
	if (src->ptr) {
		char *p = malloc (src->ptrlen);
		if (!p) {
			return false;
		}
		memcpy (p, src->ptr, src->ptrlen);
		free (dst->ptr);
		dst->ptr = p;
		dst->ptrlen = src->ptrlen;
	} else {
		R_FREE (dst->ptr);
		memcpy (dst->buf, src->buf, sizeof (dst->buf));
	}
	dst->len = src->len;
	return true;
}

R_API bool r_strbuf_reserve(RStrBuf *sb, size_t len) {
	r_return_val_if_fail (sb, false);

	if ((sb->ptr && len < sb->ptrlen) || (!sb->ptr && len < sizeof (sb->buf))) {
		return true;
	}
	char *newptr = realloc (sb->ptr, len + 1);
	if (!newptr) {
		return false;
	}
	if (!sb->ptr) {
		memcpy (newptr, sb->buf, sizeof (sb->buf));
	}
	sb->ptr = newptr;
	sb->ptrlen = len + 1;
	return true;
}

R_API bool r_strbuf_setbin(RStrBuf *sb, const ut8 *s, size_t l) {
	r_return_val_if_fail (sb && s, false);
	if (l >= sizeof (sb->buf)) {
		char *ptr = sb->ptr;
		if (!ptr || l + 1 > sb->ptrlen) {
			ptr = malloc (l + 1);
			if (!ptr) {
				return false;
			}
			R_FREE (sb->ptr);
			sb->ptrlen = l + 1;
			sb->ptr = ptr;
		}
		memcpy (ptr, s, l);
		ptr[l] = 0;
	} else {
		R_FREE (sb->ptr);
		memcpy (sb->buf, s, l);
		sb->buf[l] = 0;
	}
	sb->len = l;
	sb->weakref = false;
	return true;
}

// TODO: there's room for optimizations here
R_API bool r_strbuf_slice(RStrBuf *sb, int from, int len) {
	r_return_val_if_fail (sb && from >= 0 && len >= 0, false);
	if (from < 1 && len >= sb->len) {
		return false;
	}
	const char *s = r_strbuf_get (sb);
	const char *fr = r_str_ansi_chrn (s, from + 1);
	const char *to = r_str_ansi_chrn (s, from + len + 1);
	char *r = r_str_newlen (fr, to - fr);
	r_strbuf_fini (sb);
	r_strbuf_init (sb);
	if (from >= len) {
		r_strbuf_set (sb, "");
		free (r);
		return false;
	}
	r_strbuf_set (sb, r);
	free (r);
	return true;
}

R_API bool r_strbuf_setptr(RStrBuf *sb, char *s, int len) {
	r_return_val_if_fail (sb, false);
	if (len < 0) {
		sb->len = strlen (s);
		sb->ptrlen = sb->len + 1;
	} else {
		sb->ptrlen = len;
		sb->len = len;
	}
	sb->ptr = s;
	sb->weakref = true;
	return true;
}

R_API const char *r_strbuf_set(RStrBuf *sb, const char *s) {
	r_return_val_if_fail (sb, NULL);
	if (!s) {
		r_strbuf_init (sb);
		return r_strbuf_get (sb);
	}
	size_t len = strlen (s);
	if (!r_strbuf_setbin (sb, (const ut8*)s, len)) {
		return NULL;
	}
	sb->len = len;
	return r_strbuf_get (sb);
}

R_API const char *r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) {
	r_return_val_if_fail (sb && fmt, false);

	va_list ap;
	va_start (ap, fmt);
	const char *ret = r_strbuf_vsetf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API const char *r_strbuf_vsetf(RStrBuf *sb, const char *fmt, va_list ap) {
	r_return_val_if_fail (sb && fmt, false);

	const char *ret = NULL;
	va_list ap2;
	va_copy (ap2, ap);
	char string[1024];
	int rc = vsnprintf (string, sizeof (string), fmt, ap);
	if (rc >= sizeof (string)) {
		char *p = malloc (rc + 1);
		if (!p) {
			goto done;
		}
		vsnprintf (p, rc + 1, fmt, ap2);
		ret = r_strbuf_set (sb, p);
		free (p);
	} else if (rc >= 0) {
		ret = r_strbuf_set (sb, string);
	}
done:
	va_end (ap2);
	return ret;
}

R_API bool r_strbuf_prepend(RStrBuf *sb, const char *s) {
	r_return_val_if_fail (sb && s, false);
	int l = strlen (s);
	// fast path if no chars to append
	if (l == 0) {
		return true;
	}
	int newlen = l + sb->len;
	char *ns = malloc (newlen + 1);
	bool ret = false;
	if (ns) {
		memcpy (ns, s, l);
		char *s = sb->ptr ? sb->ptr: sb->buf;
		memcpy (ns + l, s, sb->len);
		ns[newlen] = 0;
		ret = r_strbuf_set (sb, ns);
		free (ns);
	}
	return ret;
}

R_API bool r_strbuf_append(RStrBuf *sb, const char *s) {
	r_return_val_if_fail (sb && s, false);

	int l = strlen (s);
	return r_strbuf_append_n (sb, s, l);
}

R_API bool r_strbuf_append_n(RStrBuf *sb, const char *s, size_t l) {
	r_return_val_if_fail (sb && s, false);

	if (sb->weakref) {
		return false;
	}

	// fast path if no chars to append
	if (l == 0) {
		return true;
	}

	if ((sb->len + l + 1) <= sizeof (sb->buf)) {
		memcpy (sb->buf + sb->len, s, l);
		sb->buf[sb->len + l] = 0;
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
			if (!p) {
				return false;
			}
			sb->ptr = p;
			sb->ptrlen = newlen;
		}
		if (p) {
			memcpy (p + sb->len, s, l);
			*(p + sb->len + l) = 0;
		}
	}
	sb->len += l;
	return true;
}

R_API bool r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...) {
	va_list ap;

	r_return_val_if_fail (sb && fmt, -1);

	va_start (ap, fmt);
	bool ret = r_strbuf_vappendf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API bool r_strbuf_vappendf(RStrBuf *sb, const char *fmt, va_list ap) {
	int ret;
	va_list ap2;
	char string[1024];

	r_return_val_if_fail (sb && fmt, -1);

	if (sb->weakref) {
		return false;
	}
	va_copy (ap2, ap);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret >= sizeof (string)) {
		char *p = malloc (ret + 1);
		if (!p) {
			va_end (ap2);
			return false;
		}
		*p = 0;
		vsnprintf (p, ret + 1, fmt, ap2);
		ret = r_strbuf_append (sb, p);
		free (p);
	} else if (ret >= 0) {
		ret = r_strbuf_append (sb, string);
	} else {
		ret = false;
	}
	va_end (ap2);
	return ret;
}

R_API char *r_strbuf_get(RStrBuf *sb) {
	r_return_val_if_fail (sb, NULL);
	return sb->ptr ? sb->ptr : sb->buf;
}

R_API ut8 *r_strbuf_getbin(RStrBuf *sb, int *len) {
	r_return_val_if_fail (sb, NULL);
	if (len) {
		*len = sb->len;
	}
	return (ut8 *)(sb->ptr ? sb->ptr : sb->buf);
}

static inline char *drain(RStrBuf *sb) {
	return sb->ptr
		? sb->weakref
			? r_mem_dup (sb->ptr, sb->ptrlen)
			: sb->ptr
		: strdup (sb->buf);
}

R_API char *r_strbuf_drain(RStrBuf *sb) {
	r_return_val_if_fail (sb, NULL);
	char *ret = drain (sb);
	free (sb);
	return ret;
}

R_API char *r_strbuf_drain_nofree(RStrBuf *sb) {
	r_return_val_if_fail (sb, NULL);
	char *ret = drain (sb);
	sb->ptr = NULL;
	sb->len = 0;
	sb->buf[0] = '\0';
	return ret;
}

R_API void r_strbuf_free(RStrBuf *sb) {
	if (sb) {
		r_strbuf_fini (sb);
		free (sb);
	}
}

R_API void r_strbuf_fini(RStrBuf *sb) {
	if (sb && !sb->weakref) {
		R_FREE (sb->ptr);
		sb->len = 0;
		sb->buf[0] = '\0';
	}
}
