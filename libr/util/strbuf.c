/* radare - LGPL - Copyright 2013-2026 - pancake */

#include <r_util.h>

#define SBSZ 512

// Base growth: +12.5%, with adaptive slack to avoid size-class boundaries
static inline size_t growlog(size_t cap, size_t required) {
	// assume cap can't be zero because minimum if sizeof (buf)
	if (cap >= required) {
		return cap;
	}
	size_t grown = cap + (cap >> 3); // +12.5%
	if (grown < required) {
		grown = required + (required >> 3);
	}
	// avoids sharp size-class boundaries
	return grown + (grown < 1024? 64: (grown >> 4));
}

static bool strbuf_vprintf(RStrBuf *sb, const char *fmt, va_list ap, size_t len, bool prepend) {
	size_t required;
	if (r_add_overflow (sb->len, len + 1, &required) || !r_strbuf_reserve (sb, required - 1)) {
		return false;
	}
	char *buf = r_strbuf_get (sb);
	const size_t oldlen = sb->len;
	if (prepend && oldlen > 0) {
		memmove (buf + len, buf, oldlen);
	}
	char first = prepend && oldlen > 0? buf[len]: 0;
	int ret = vsnprintf (buf + (prepend? 0: oldlen), len + 1, fmt, ap);
	if (ret < 0 || (size_t)ret != len) {
		if (prepend && oldlen > 0) {
			buf[len] = first;
			memmove (buf, buf + len, oldlen);
		}
		buf[oldlen] = 0;
		return false;
	}
	if (prepend && oldlen > 0) {
		buf[len] = first;
	}
	sb->len += len;
	buf[sb->len] = 0;
	return true;
}

static bool strbuf_setbin_free(RStrBuf *sb, char *s) {
	const bool ret = s && r_strbuf_setbin (sb, (const ut8 *)s, strlen (s));
	free (s);
	return ret;
}

R_API RStrBuf *R_NONNULL r_strbuf_new(const char *str) {
	RStrBuf *s = R_NEW0 (RStrBuf);
	if (str) {
		r_strbuf_set (s, str);
	}
	return s;
}

R_API RStrBuf *r_strbuf_newf(const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (fmt, NULL);
	RStrBuf *sb = R_NEW0 (RStrBuf);
	va_list ap;
	va_start (ap, fmt);
	R_UNUSED_RESULT (r_strbuf_vappendf (sb, fmt, ap));
	va_end (ap);
	return sb;
}

R_API bool r_strbuf_equals(RStrBuf *sa, RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (sa && sb, false);
	if (sa->len != sb->len) {
		return false;
	}
	return strcmp (r_strbuf_get (sa), r_strbuf_get (sb)) == 0;
}

R_API bool r_strbuf_is_empty(RStrBuf *sb) {
	return sb->len == 0;
}

R_API int r_strbuf_length(RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (sb, 0);
	return sb->len;
}

R_API size_t r_strbuf_size(RStrBuf *sb) {
	// return its capacity
	R_RETURN_VAL_IF_FAIL (sb, 0);
	return sb->ptr? sb->ptrlen: sizeof (sb->buf);
}

R_API void r_strbuf_init(RStrBuf *sb) {
	R_RETURN_IF_FAIL (sb);
	*sb = (const RStrBuf){ 0 };
}

R_API const char *r_strbuf_initf(RStrBuf *sb, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (sb && fmt, NULL);
	r_strbuf_init (sb);
	va_list ap;
	va_start (ap, fmt);
	const char *r = r_strbuf_vsetf (sb, fmt, ap);
	va_end (ap);
	return r;
}

R_API bool r_strbuf_copy(RStrBuf *dst, RStrBuf *src) {
	R_RETURN_VAL_IF_FAIL (dst && src, false);
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
		dst->ptrlen = 0;
		R_FREE (dst->ptr);
		memcpy (dst->buf, src->buf, sizeof (dst->buf));
	}
	dst->len = src->len;
	dst->weakref = false;
	return true;
}

R_API bool r_strbuf_reserve(RStrBuf *sb, size_t len) {
	R_RETURN_VAL_IF_FAIL (sb, false);

	len = R_MAX (len, sb->len);
	if (!sb->weakref && ((sb->ptr && len < sb->ptrlen) || (!sb->ptr && len < sizeof (sb->buf)))) {
		return true;
	}
	size_t newlen;
	if (r_add_overflow (len, (size_t)1, &newlen)) {
		return false;
	}
	char *old_ptr = sb->weakref? NULL: sb->ptr;
	char *newptr = realloc (old_ptr, newlen);
	if (!newptr) {
		return false;
	}
	if (!old_ptr) {
		memcpy (newptr, sb->ptr? sb->ptr: sb->buf, sb->len);
	}
	newptr[sb->len] = 0;
	sb->weakref = false;
	sb->ptr = newptr;
	sb->ptrlen = newlen;
	return true;
}

R_API bool r_strbuf_setbin(RStrBuf *sb, const ut8 *s, size_t l) {
	R_RETURN_VAL_IF_FAIL (sb && s, false);
	if (l > ST32_MAX) {
		return false;
	}
	if (l >= sizeof (sb->buf)) {
		if (!r_strbuf_reserve (sb, l)) {
			return false;
		}
		memcpy (sb->ptr, s, l);
		sb->ptr[l] = 0;
	} else {
		if (!sb->weakref) {
			R_FREE (sb->ptr);
		} else {
			sb->ptr = NULL;
		}
		memcpy (sb->buf, s, l);
		sb->buf[l] = 0;
	}
	sb->len = l;
	sb->weakref = false;
	return true;
}

R_API bool r_strbuf_slice(RStrBuf *sb, int from, int len) {
	R_RETURN_VAL_IF_FAIL (sb && from >= 0 && len >= 0, false);
	if (from < 1 && len >= sb->len) {
		return false;
	}
	if (from >= len) {
		r_strbuf_set (sb, "");
		return false;
	}
	char *s = r_strbuf_get (sb);
	// Scan from the start position, then continue from there to find the end,
	// avoiding a full re-scan from the beginning. Shift the slice in-place.
	const char *fr = r_str_ansi_chrn (s, from + 1);
	const char *to = r_str_ansi_chrn (fr, len + 1);
	size_t slice_len = to - fr;
	if (sb->weakref) {
		char *ns = malloc (slice_len + 1);
		if (!ns) {
			return false;
		}
		memcpy (ns, fr, slice_len);
		ns[slice_len] = 0;
		sb->ptr = ns;
		sb->ptrlen = slice_len + 1;
		sb->weakref = false;
	} else {
		memmove (s, fr, slice_len);
		s[slice_len] = 0;
	}
	sb->len = slice_len;
	return true;
}

R_API bool r_strbuf_setptr(RStrBuf *sb, char *s, int len) {
	R_RETURN_VAL_IF_FAIL (sb, false);
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
	R_RETURN_VAL_IF_FAIL (sb, NULL);
	if (!s) {
		r_strbuf_init (sb);
		return r_strbuf_get (sb);
	}
	size_t len = strlen (s);
	if (!r_strbuf_setbin (sb, (const ut8 *)s, len)) {
		return NULL;
	}
	sb->len = len;
	return r_strbuf_get (sb);
}

R_API const char *r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (sb && fmt, false);

	va_list ap;
	va_start (ap, fmt);
	const char *ret = r_strbuf_vsetf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API const char *r_strbuf_vsetf(RStrBuf *sb, const char *fmt, va_list ap) {
	R_RETURN_VAL_IF_FAIL (sb && fmt, false);

	const char *ret = NULL;
	va_list ap2;
	va_copy (ap2, ap);
	char string[SBSZ];
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
	R_RETURN_VAL_IF_FAIL (sb && s, false);
	return r_strbuf_prepend_n (sb, s, strlen (s));
}

R_API bool r_strbuf_append(RStrBuf *sb, const char *s) {
	R_RETURN_VAL_IF_FAIL (sb && s, false);

	size_t l = strlen (s);
	return r_strbuf_append_n (sb, s, l);
}

R_API bool r_strbuf_append_n(RStrBuf *sb, const char *s, size_t l) {
	R_RETURN_VAL_IF_FAIL (sb && s, false);
	if (l > ST32_MAX) {
		R_LOG_WARN ("Negative length used in r_strbuf_append_n");
		return false;
	}

	size_t required;
	if (r_add_overflow (sb->len, l + 1, &required)) {
		return false;
	}
	if (sb->weakref || l == 0) {
		return !sb->weakref;
	}

	if (required <= sizeof (sb->buf)) {
		memcpy (sb->buf + sb->len, s, l);
		sb->buf[sb->len + l] = 0;
		sb->len += l;
		R_FREE (sb->ptr);
		return true;
	}

	char *p = sb->ptr;
	size_t current = sb->ptr? sb->ptrlen: sizeof (sb->buf);

	// Only grow if current capacity is insufficient
	if (current < required) {
		size_t newlen = growlog (current, required);
		if (!sb->ptr) {
			p = malloc (newlen);
			if (!p) {
				return false;
			}
			if (sb->len > 0) {
				memcpy (p, sb->buf, sb->len);
			}
		} else {
			p = realloc (sb->ptr, newlen);
			if (!p) {
				return false;
			}
		}
		sb->ptr = p;
		sb->ptrlen = newlen;
	}

	memcpy ((sb->ptr? sb->ptr: sb->buf) + sb->len, s, l);
	char *buf = sb->ptr? sb->ptr: sb->buf;
	buf[sb->len + l] = 0;
	sb->len += l;
	return true;
}

R_API bool r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...) {
	va_list ap;

	R_RETURN_VAL_IF_FAIL (sb && fmt, false);

	va_start (ap, fmt);
	const bool ret = r_strbuf_vappendf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API bool r_strbuf_vappendf(RStrBuf *sb, const char *fmt, va_list ap) {
	va_list ap2;
	char string[SBSZ];

	R_RETURN_VAL_IF_FAIL (sb && fmt, false);

	if (sb->weakref) {
		return false;
	}
	va_copy (ap2, ap);
	int ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret >= sizeof (string)) {
		ret = strbuf_vprintf (sb, fmt, ap2, ret, false);
	} else if (ret >= 0) {
		ret = r_strbuf_append_n (sb, string, ret);
	} else {
		ret = false;
	}
	va_end (ap2);
	return ret;
}

R_API bool r_strbuf_prependf(RStrBuf *sb, const char *fmt, ...) {
	va_list ap;

	R_RETURN_VAL_IF_FAIL (sb && fmt, false);

	va_start (ap, fmt);
	const bool ret = r_strbuf_vprependf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API bool r_strbuf_prepend_n(RStrBuf *sb, const char *s, size_t l) {
	R_RETURN_VAL_IF_FAIL (sb && s, false);
	if (l > ST32_MAX) {
		R_LOG_WARN ("Negative length used in r_strbuf_prepend_n");
		return false;
	}

	if (sb->weakref || l == 0) {
		return !sb->weakref;
	}

	if ((sb->len + l + 1) <= sizeof (sb->buf)) {
		/* Guard to help static analyzers reason about bounds. */
		R_RETURN_VAL_IF_FAIL (l < sizeof (sb->buf), false);
		memmove (sb->buf + l, sb->buf, sb->len);
		memcpy (sb->buf, s, l);
		sb->buf[sb->len + l] = 0;
		sb->len += l;
		R_FREE (sb->ptr);
		return true;
	}

	char *p = sb->ptr;
	size_t required = sb->len + l + 1;
	size_t current = sb->ptr? sb->ptrlen: sizeof (sb->buf);

	// Only grow if current capacity is insufficient
	if (current < required) {
		size_t newlen = growlog (current, required);
		if (!sb->ptr) {
			p = malloc (newlen);
			if (!p) {
				return false;
			}
			if (sb->len > 0) {
				memcpy (p + l, sb->buf, sb->len);
			}
		} else {
			p = realloc (sb->ptr, newlen);
			if (!p) {
				return false;
			}
			memmove (p + l, p, sb->len);
		}
		sb->ptr = p;
		sb->ptrlen = newlen;
	} else if (sb->ptr) {
		memmove (p + l, p, sb->len);
	}

	memcpy ((sb->ptr? sb->ptr: sb->buf), s, l);
	char *buf = sb->ptr? sb->ptr: sb->buf;
	buf[sb->len + l] = 0;
	sb->len += l;
	return true;
}

R_API bool r_strbuf_pad(RStrBuf *sb, char ch, int sz) {
	R_RETURN_VAL_IF_FAIL (sb, false);
	if (sz < 1) {
		return true;
	}
	if (!r_strbuf_reserve (sb, sb->len + sz)) {
		return false;
	}
	char *buf = sb->ptr? sb->ptr: sb->buf;
	memset (buf + sb->len, ch, sz);
	buf[sb->len + sz] = 0;
	sb->len += sz;
	return true;
}

R_API bool r_strbuf_vprependf(RStrBuf *sb, const char *fmt, va_list ap) {
	va_list ap2;
	char string[SBSZ];

	R_RETURN_VAL_IF_FAIL (sb && fmt, false);

	if (sb->weakref) {
		return false;
	}
	va_copy (ap2, ap);
	int ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret >= sizeof (string)) {
		ret = strbuf_vprintf (sb, fmt, ap2, ret, true);
	} else if (ret >= 0) {
		ret = r_strbuf_prepend_n (sb, string, ret);
	} else {
		ret = false;
	}
	va_end (ap2);
	return ret;
}

R_API char *r_strbuf_get(RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (sb, NULL);
	return sb->ptr? sb->ptr: sb->buf;
}

R_API ut8 *r_strbuf_getbin(RStrBuf *sb, int *len) {
	R_RETURN_VAL_IF_FAIL (sb, NULL);
	if (len) {
		*len = sb->len;
	}
	return (ut8 *)(sb->ptr ? sb->ptr : sb->buf);
}

static inline char *drain(RStrBuf *sb) {
	if (sb->ptr) {
		if (sb->weakref) {
			return r_mem_dup (sb->ptr, sb->len);
		}
		// realloc down the allocation
		sb->ptrlen = sb->len;
		return realloc (sb->ptr, sb->len + 1);
	}
	return r_str_ndup (sb->buf, sb->len);
}

R_API char *r_strbuf_drain(RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (sb, NULL);
	char *ret = drain (sb);
	sb->ptr = NULL;
	sb->ptrlen = 0;
	free (sb);
	return ret;
}

R_API char *r_strbuf_tostring(RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (sb, NULL);
	void *tmp = drain (sb);
	sb->ptr = tmp;
	return tmp;
}

R_API char *r_strbuf_drain_nofree(RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (sb, NULL);
	char *ret = drain (sb);
	sb->ptr = NULL;
	sb->len = 0;
	sb->buf[0] = '\0';
	return ret;
}

R_API bool r_strbuf_replace(RStrBuf *sb, const char *key, const char *val) {
	R_RETURN_VAL_IF_FAIL (sb && key && val, false);
	return strbuf_setbin_free (sb, r_str_replace (strdup (r_strbuf_get (sb)), key, val, 0));
}

R_API bool r_strbuf_replacef(RStrBuf *sb, const char *key, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (sb && key && fmt, false);
	RStrBuf sb_tmp = { 0 };
	va_list ap;
	va_start (ap, fmt);
	const char *val = r_strbuf_vsetf (&sb_tmp, fmt, ap);
	va_end (ap);
	char *tmp = val? r_str_replace (strdup (r_strbuf_get (sb)), key, val, 0): NULL;
	r_strbuf_fini (&sb_tmp);
	return strbuf_setbin_free (sb, tmp);
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
		sb->ptrlen = 0;
	}
}

R_API void r_strbuf_trim(RStrBuf *sb) {
	R_RETURN_IF_FAIL (sb);
	char *s = sb->weakref? strdup (r_strbuf_get (sb)): r_strbuf_get (sb);
	if (!s) {
		return;
	}
	int len = r_str_ntrim (s, (int)sb->len);
	if (sb->weakref) {
		r_strbuf_setbin (sb, (const ut8 *)s, len);
		free (s);
	} else {
		sb->len = len;
	}
}
