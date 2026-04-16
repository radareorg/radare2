/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

R_API const char *r_strs_find_strs(RStrs s, RStrs needle) {
	const size_t sl = r_strs_len (s);
	const size_t nl = r_strs_len (needle);
	if (nl == 0) {
		return s.a;
	}
	if (nl > sl) {
		return NULL;
	}
	if (sl > INT_MAX || nl > INT_MAX) {
		return NULL;
	}
	return (const char *)r_mem_mem ((const ut8 *)s.a, (int)sl, (const ut8 *)needle.a, (int)nl);
}

R_API const char *r_strs_findc(RStrs s, char c) {
	R_RETURN_VAL_IF_FAIL (s.a, NULL);
	return (const char *)memchr (s.a, c, r_strs_len (s));
}

R_API const char *r_strs_find_any(RStrs s, const char *set) {
	if (!set || !*set) {
		return NULL;
	}
	const char *p;
	for (p = s.a; p < s.b; p++) {
		if (strchr (set, *p)) {
			return p;
		}
	}
	return NULL;
}

R_API void r_strs_skip_chars(RStrs *s, const char *set) {
	R_RETURN_IF_FAIL (s && set);
	while (s->a < s->b && strchr (set, *s->a)) {
		s->a++;
	}
}

R_API RStrs r_strs_take_ident(RStrs *s) {
	R_RETURN_VAL_IF_FAIL (s, ((RStrs) { 0 }));
	RStrs out = { s->a, s->a };
	while (s->a < s->b) {
		const unsigned char c = (unsigned char)*s->a;
		if (!isalnum (c) && c != '_') {
			break;
		}
		s->a++;
	}
	out.b = s->a;
	return out;
}

R_API bool r_strs_next_token(RStrs *s, const char *seps, RStrs *out) {
	R_RETURN_VAL_IF_FAIL (s && seps && out, false);
	r_strs_skip_chars (s, seps);
	if (r_strs_empty (*s)) {
		out->a = out->b = s->b;
		return false;
	}
	out->a = s->a;
	while (s->a < s->b && !strchr (seps, *s->a)) {
		s->a++;
	}
	out->b = s->a;
	return true;
}

R_API char *r_strs_tostring(RStrs s) {
	return r_str_ndup (s.a, (int)r_strs_len (s));
}

R_API ut64 r_strs_tonum(RStrs s) {
	char buf[64];
	const size_t n = r_strs_len (s);
	if (n == 0) {
		return 0;
	}
	if (n < sizeof (buf)) {
		memcpy (buf, s.a, n);
		buf[n] = 0;
		return r_num_get (NULL, buf);
	}
	char *tmp = r_strs_tostring (s);
	const ut64 r = tmp? r_num_get (NULL, tmp): 0;
	free (tmp);
	return r;
}

R_API st64 r_strs_tosnum(RStrs s, bool *ok) {
	char buf[64];
	const size_t n = r_strs_len (s);
	if (n == 0) {
		if (ok) {
			*ok = false;
		}
		return 0;
	}
	const char *err = NULL;
	st64 r;
	if (n < sizeof (buf)) {
		memcpy (buf, s.a, n);
		buf[n] = 0;
		r = (st64)r_num_get_err (NULL, buf, &err);
	} else {
		char *tmp = r_strs_tostring (s);
		r = tmp? (st64)r_num_get_err (NULL, tmp, &err): 0;
		free (tmp);
	}
	if (ok) {
		*ok = (err == NULL);
	}
	return r;
}
