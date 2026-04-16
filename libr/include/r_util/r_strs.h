#ifndef R_STRS_H
#define R_STRS_H

#include <r_types.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_strs_t {
	const char *a;
	const char *b;
} RStrs;

#define R_STRS_LIT(s) r_strs_from_len ((s), sizeof ("" s) - 1)

/* Constructors */
static inline RStrs r_strs_new(const char *a, const char *b) {
	RStrs r = { a, b };
	return r;
}

static inline RStrs r_strs_from_len(const char *s, size_t n) {
	RStrs r = { s, s? s + n: NULL };
	return r;
}

static inline RStrs r_strs_from(const char *s) {
	RStrs r = { s, s? s + strlen (s): NULL };
	return r;
}

/* Queries */
static inline size_t r_strs_len(RStrs s) {
	return (s.a && s.b > s.a)? (size_t)(s.b - s.a): 0;
}

static inline bool r_strs_empty(RStrs s) {
	return !s.a || s.b <= s.a;
}

/* Subslicing */
static inline RStrs r_strs_sub(RStrs s, size_t from, size_t to) {
	const size_t l = r_strs_len (s);
	if (from > l) {
		from = l;
	}
	if (to > l) {
		to = l;
	}
	if (to < from) {
		to = from;
	}
	RStrs r = { s.a + from, s.a + to };
	return r;
}

/* Navigation. Mutators require a valid `s`; passing NULL is a caller bug. */
static inline bool r_strs_advance(RStrs *s, size_t n) {
	if (n > r_strs_len (*s)) {
		s->a = s->b;
		return false;
	}
	s->a += n;
	return true;
}

/* Whitespace trimming */
static inline void r_strs_trim(RStrs *s) {
	while (s->a < s->b && isspace ((unsigned char)*s->a)) {
		s->a++;
	}
	while (s->b > s->a && isspace ((unsigned char)s->b[-1])) {
		s->b--;
	}
}

/* Equality / prefix — canonical slice versions */
static inline bool r_strs_equals(RStrs a, RStrs b) {
	const size_t la = r_strs_len (a);
	return la == r_strs_len (b) && (la == 0 || !memcmp (a.a, b.a, la));
}

static inline bool r_strs_startswith_strs(RStrs s, RStrs prefix) {
	const size_t n = r_strs_len (prefix);
	return n == 0 || (r_strs_len (s) >= n && !memcmp (s.a, prefix.a, n));
}

/* C-string convenience wrappers — strlen folds to a constant for literals */
static inline bool r_strs_equals_str(RStrs s, const char *str) {
	return r_strs_equals (s, r_strs_from (str));
}

static inline bool r_strs_startswith(RStrs s, const char *prefix) {
	return r_strs_startswith_strs (s, r_strs_from (prefix));
}

/* Search (out of line primitives) */
R_API const char *r_strs_find_strs(RStrs s, RStrs needle);
R_API const char *r_strs_findc(RStrs s, char c);
R_API const char *r_strs_find_any(RStrs s, const char *set);

/* Char-set skip, tokenization (out of line) */
R_API void r_strs_skip_chars(RStrs *s, const char *set);
R_API RStrs r_strs_take_ident(RStrs *s);
R_API bool r_strs_next_token(RStrs *s, const char *seps, RStrs *out);

/* Splitting — inline wrappers around the search primitives. Both `head` and
 * `tail` must be non-NULL; pass a throwaway slot if a side is unwanted. */
static inline bool r_strs_split(RStrs s, char sep, RStrs *head, RStrs *tail) {
	const char *p = r_strs_findc (s, sep);
	if (!p) {
		*head = s;
		tail->a = tail->b = s.b;
		return false;
	}
	head->a = s.a; head->b = p;
	tail->a = p + 1; tail->b = s.b;
	return true;
}

static inline bool r_strs_split_any(RStrs s, const char *seps, RStrs *head, RStrs *tail) {
	const char *p = r_strs_find_any (s, seps);
	if (!p) {
		*head = s;
		tail->a = tail->b = s.b;
		return false;
	}
	head->a = s.a; head->b = p;
	tail->a = p + 1; tail->b = s.b;
	return true;
}

static inline bool r_strs_split_strs(RStrs s, RStrs sep, RStrs *head, RStrs *tail) {
	const size_t n = r_strs_len (sep);
	const char *p = n? r_strs_find_strs (s, sep): NULL;
	if (!p) {
		*head = s;
		tail->a = tail->b = s.b;
		return false;
	}
	head->a = s.a; head->b = p;
	tail->a = p + n; tail->b = s.b;
	return true;
}

/* Conversion (out of line) */
R_API char *r_strs_tostring(RStrs s);
R_API ut64 r_strs_tonum(RStrs s);
R_API st64 r_strs_tosnum(RStrs s, bool *ok);

#ifdef __cplusplus
}
#endif

#endif
