/* radare2 - LGPL - Copyright 2022 - pancake */

// radare-stack-string-implementation
#include <r_util.h>

// #define r_string_get(x) ((char *)((x).ptr?(x).ptr:(char *)&(x).buf))
#define r_string_free(x) if (!(x).weak) {free ((x).ptr);}

R_API char *r_string_get(const RString *s, int *len) {
	if (len) {
		*len = s->len;
	}
	if (s->len < 1) {
		if (len) {
			*len = 0;
		}
		return strdup ("");
	}
	if (s->weak) {
		return r_str_ndup (s->str, s->len);
	}
	if (len) {
		*len = s->len;
	}
	return strdup (s->str);
}

R_API RString r_string_new(const char *is, int len) {
	RString s = {0};
	if (is) {
		size_t sl = len < 0 ? strlen (is): len;
		if (sl >= sizeof (s.buf)) {
			s.ptr = strdup (is);
			s.str = s.ptr;
		} else {
			memcpy (s.buf, is, sl + 1);
			s.str = s.buf;
		}
		s.len = sl;
	}
	return s;
}

R_API RString r_string_from(const char *is, int len) {
	RString s = {0};
	if (is) {
		s.weak = true;
		s.ptr = (char *)is;
		s.str = s.ptr;
		s.len = len;
	}
	return s;
}

R_API void r_string_unweak(RString *a) {
	a->weak = false;
	a->ptr = r_str_ndup (a->ptr, a->len);
	a->str = a->ptr;
}

R_API void r_string_trim(RString *s) {
	if (s->weak) {
		const char *trimmed = r_str_trim_head_ro (s->str);
		s->str = (char *)trimmed;
		if (s->ptr) {
			s->ptr = s->str;
		}
		return;
	}
	s->len = r_str_ntrim (s->str, s->len);
}

R_API RString r_string_newf(const char *fmt, ...) {
	RString s = {0};
	va_list ap, ap2;

	va_start (ap, fmt);
	if (!strchr (fmt, '%')) {
		va_end (ap);
		return r_string_new (fmt, strlen (fmt));
	}
	va_copy (ap2, ap);
	int ret = vsnprintf (NULL, 0, fmt, ap2);
	ret++;
	char *p = NULL;
	bool myp = false;
	if (ret >= sizeof (s.buf)) {
		myp = true;
		p = calloc (1, ret);
	} else {
		p = (char *)&s.buf;
	}
	if (p) {
		(void)vsnprintf (p, ret, fmt, ap);
	}
	va_end (ap2);
	va_end (ap);
	if (myp) {
		free (p);
	}
	return s; //r_string_from (p, ret);
}

R_API bool r_string_append(RString *a, const char *s) {
	if (a->weak) {
		// error. weak strings cannot be modified.. unless well you unweak them
		return false;
	}
	size_t olen = a->len;
	size_t slen = strlen (s);
	size_t tlen = olen + slen;
	if (tlen >= sizeof (a->buf)) {
		char *aptr = a->ptr;
		a->ptr = r_str_newf ("%s%s", a->str, s);
		a->str = a->ptr;
		a->len = tlen;
		free (aptr);
	} else {
		memcpy (a->buf + olen, s, slen + 1);
		a->len = tlen;
		a->str = a->buf;
	}
	return true;
}

R_API void r_string_appendf(RString *a, const char *fmt, ...) {
	RString s = {0};
	va_list ap, ap2;

	va_start (ap, fmt);
	if (!strchr (fmt, '%')) {
		va_end (ap);
		r_string_append (a, fmt);
		return;
	}
	va_copy (ap2, ap);
	int ret = vsnprintf (NULL, 0, fmt, ap2);
	ret++;
	char *p = NULL;
	bool myp = false;
	if (ret >= sizeof (s.buf)) {
		myp = true;
		p = calloc (1, ret);
	} else {
		p = (char *)&s.buf;
	}
	if (p) {
		(void)vsnprintf (p, ret, fmt, ap);
	}
	va_end (ap2);
	va_end (ap);
	r_string_append (a, p);
	if (myp) {
		free (p);
	}
}

#if 0
int main() {
	int i;
#if 1
	// 10.4s
	for (i = 0; i < 10000000; i++) {
		RString s = r_string_new ("  hello world", -1);
		r_string_appendf (&s, " [PATATA %s:%d]  ", "jeje", 23);
		r_string_trim (&s);
		printf ("%s\n", s.str);
		printf ("%s\n", r_string_newf ("rstring %s", "rulez").str);
		r_string_free (s);
	}
#else
	// 13.8s
	for (i = 0; i < 10000000; i++) {
		RStrBuf *sb = r_strbuf_new ("  hello world");
		r_strbuf_appendf (sb, " [PATATA %s:%d]  ", "jeje", 23);
		char *ss = r_strbuf_drain (sb);
		r_str_trim (ss);
		printf ("%s\n", ss);
		char *lala = r_str_newf ("rstring %s", "rulez");
		printf ("%s\n", lala);
		free (lala);
		free (ss);
	}
#endif
}
#endif
