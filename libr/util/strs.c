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

R_API void r_strs_trim_chars(RStrs *s, const char *set) {
	R_RETURN_IF_FAIL (s && set);
	while (s->a < s->b && strchr (set, *s->a)) {
		s->a++;
	}
	while (s->b > s->a && strchr (set, s->b[-1])) {
		s->b--;
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

R_API ut64 r_strs_tonum(RStrs s, int base, bool *error) {
	if (error) {
		*error = false;
	}
	const size_t n = r_strs_len (s);
	if (n == 0) {
		if (error) {
			*error = true;
		}
		return 0;
	}
	const char *p = s.a;
	const char *const e = s.b;
	bool is_hex;
	switch (base) {
	case 16:
		is_hex = true;
		if (n >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
			p += 2;
		}
		break;
	case 10:
		is_hex = false;
		break;
	case 0:
		if (n >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
			is_hex = true;
			p += 2;
		} else {
			is_hex = false;
		}
		break;
	default:
		if (error) {
			*error = true;
		}
		return 0;
	}
	if (p >= e) {
		if (error) {
			*error = true;
		}
		return 0;
	}
	ut64 v = 0;
	if (is_hex) {
		while (p < e) {
			const unsigned char c = (unsigned char)*p++;
			ut64 d;
			if (c >= '0' && c <= '9') {
				d = c - '0';
			} else if (c >= 'a' && c <= 'f') {
				d = c - 'a' + 10;
			} else if (c >= 'A' && c <= 'F') {
				d = c - 'A' + 10;
			} else {
				if (error) {
					*error = true;
				}
				return 0;
			}
			v = (v << 4) | d;
		}
	} else {
		while (p < e) {
			const unsigned char c = (unsigned char)*p++;
			if (c < '0' || c > '9') {
				if (error) {
					*error = true;
				}
				return 0;
			}
			v = v * 10 + (c - '0');
		}
	}
	return v;
}

R_API RStrs r_strs_u64hex(char *buf, size_t cap, ut64 n) {
	if (!buf || cap < 19) {
		return (RStrs) { NULL, NULL };
	}
	if (n == 0) {
		buf[0] = '0';
		buf[1] = '\0';
		return r_strs_from_len (buf, 1);
	}
	static const char lookup[] = "0123456789abcdef";
	char tmp[16];
	int t = 0;
	while (n) {
		tmp[t++] = lookup[n & 0xf];
		n >>= 4;
	}
	buf[0] = '0';
	buf[1] = 'x';
	int j;
	for (j = 0; j < t; j++) {
		buf[2 + j] = tmp[t - 1 - j];
	}
	const size_t len = (size_t)(t + 2);
	buf[len] = '\0';
	return r_strs_from_len (buf, len);
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
