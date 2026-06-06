// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef R2_CXX2_INTERNAL_H
#define R2_CXX2_INTERNAL_H

typedef struct {
	const char *code;
	const char *spelling;
} CXX2Op;

static inline bool cxx2_strvec_push(char ***vec, int *len, int *cap, const char *s, int max) {
	if (!s || (max > 0 && *len >= max)) {
		return false;
	}
	if (*len == *cap) {
		if (*cap > INT_MAX / 2) {
			return false;
		}
		int ncap = *cap ? *cap * 2 : 8;
		if (max > 0 && ncap > max) {
			ncap = max;
		}
		char **nv = realloc (*vec, ncap * sizeof (char *));
		if (!nv) {
			return false;
		}
		*vec = nv;
		*cap = ncap;
	}
	char *dup = strdup (s);
	if (!dup) {
		return false;
	}
	(*vec)[(*len)++] = dup;
	return true;
}

static inline void cxx2_strvec_truncate(char **vec, int *len, int n) {
	while (*len > n) {
		free (vec[--*len]);
	}
}

static inline void cxx2_strvec_fini(char ***vec, int *len) {
	cxx2_strvec_truncate (*vec, len, 0);
	free (*vec);
	*vec = NULL;
}

static inline const CXX2Op *cxx2_op_lookup(const CXX2Op *ops, const char *s, size_t n) {
	int i;
	for (i = 0; ops[i].code; i++) {
		if (strlen (ops[i].code) == n && !strncmp (s, ops[i].code, n)) {
			return &ops[i];
		}
	}
	return NULL;
}

static inline char *cxx2_basename(const char *qual) {
	if (!qual) {
		return NULL;
	}
	const char *base = qual;
	const char *p;
	int depth = 0;
	for (p = qual; p && *p; p++) {
		if (*p == '<') {
			depth++;
		} else if (*p == '>' && depth > 0) {
			depth--;
		} else if (depth == 0 && p[0] == ':' && p[1] == ':') {
			base = p + 2;
			p++;
		}
	}
	for (p = base; *p && *p != '<'; p++) {
	}
	return r_str_ndup (base, p - base);
}

#endif
