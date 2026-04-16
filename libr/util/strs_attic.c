/* radare - LGPL - Copyright 2026 - pancake */

//RStrs attic — parked public APIs for the string slices

#include <r_util.h>

static inline char r_strs_first(RStrs s) {
	return r_strs_empty (s)? 0: s.a[0];
}

static inline char r_strs_last(RStrs s) {
	return r_strs_empty (s)? 0: s.b[-1];
}

static inline RStrs r_strs_head(RStrs s, size_t n) {
	const size_t l = r_strs_len (s);
	if (n > l) {
		n = l;
	}
	RStrs r = { s.a, s.a + n };
	return r;
}

static inline RStrs r_strs_tail(RStrs s, size_t n) {
	const size_t l = r_strs_len (s);
	if (n > l) {
		n = l;
	}
	RStrs r = { s.b - n, s.b };
	return r;
}

static inline RStrs r_strs_drop(RStrs s, size_t n) {
	const size_t l = r_strs_len (s);
	if (n > l) {
		n = l;
	}
	RStrs r = { s.a + n, s.b };
	return r;
}

static inline RStrs r_strs_drop_back(RStrs s, size_t n) {
	const size_t l = r_strs_len (s);
	if (n > l) {
		n = l;
	}
	RStrs r = { s.a, s.b - n };
	return r;
}

static inline char r_strs_pop_front(RStrs *s) {
	if (r_strs_empty (*s)) {
		return 0;
	}
	const char c = *s->a;
	s->a++;
	return c;
}

static inline char r_strs_pop_back(RStrs *s) {
	if (r_strs_empty (*s)) {
		return 0;
	}
	s->b--;
	return *s->b;
}

static inline void r_strs_ltrim(RStrs *s) {
	while (s->a < s->b && isspace ((unsigned char)*s->a)) {
		s->a++;
	}
}

static inline void r_strs_rtrim(RStrs *s) {
	while (s->b > s->a && isspace ((unsigned char)s->b[-1])) {
		s->b--;
	}
}

static inline bool r_strs_endswith_strs(RStrs s, RStrs suffix) {
	const size_t n = r_strs_len (suffix);
	const size_t l = r_strs_len (s);
	return n == 0 || (l >= n && !memcmp (s.b - n, suffix.a, n));
}

static inline bool r_strs_endswith(RStrs s, const char *suffix) {
	return r_strs_endswith_strs (s, r_strs_from (suffix));
}

static inline const char *r_strs_find(RStrs s, const char *needle) {
	return r_strs_find_strs (s, r_strs_from (needle));
}

static inline bool r_strs_contains(RStrs s, const char *needle) {
	return r_strs_find (s, needle) != NULL;
}

static inline bool r_strs_contains_char(RStrs s, char c) {
	return r_strs_findc (s, c) != NULL;
}

static inline bool r_strs_split_str(RStrs s, const char *sep, RStrs *head, RStrs *tail) {
	return r_strs_split_strs (s, r_strs_from (sep), head, tail);
}

R_API int r_strs_cmp(RStrs a, RStrs b) {
	const size_t la = r_strs_len (a);
	const size_t lb = r_strs_len (b);
	const size_t m = R_MIN (la, lb);
	if (m > 0) {
		const int r = memcmp (a.a, b.a, m);
		if (r) {
			return r;
		}
	}
	return (la < lb)? -1: (la > lb)? 1: 0;
}

R_API int r_strs_cmpi(RStrs a, RStrs b) {
	const size_t la = r_strs_len (a);
	const size_t lb = r_strs_len (b);
	const size_t m = R_MIN (la, lb);
	if (m > 0) {
		const int r = r_str_ncasecmp (a.a, b.a, m);
		if (r) {
			return r;
		}
	}
	return (la < lb)? -1: (la > lb)? 1: 0;
}

R_API const char *r_strs_rfindc(RStrs s, char c) {
	R_RETURN_VAL_IF_FAIL (s.a, NULL);
	size_t i = r_strs_len (s);
	while (i-- > 0) {
		if (s.a[i] == c) {
			return s.a + i;
		}
	}
	return NULL;
}

R_API size_t r_strs_ncopy(char *dst, size_t dstsize, RStrs s) {
	if (!dst || dstsize == 0) {
		return 0;
	}
	size_t n = r_strs_len (s);
	if (n >= dstsize) {
		n = dstsize - 1;
	}
	if (n) {
		memcpy (dst, s.a, n);
	}
	dst[n] = 0;
	return n;
}
