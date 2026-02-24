/* radare - LGPL - Copyright 2009-2026 - pancake */

#include <r_util.h>

// lookup table for r_name_validate_char: true = valid (alnum or . : _)
static const bool valid_name_char[256] = {
	['.'] = true,
	['0'] = true, ['1'] = true, ['2'] = true, ['3'] = true, ['4'] = true,
	['5'] = true, ['6'] = true, ['7'] = true, ['8'] = true, ['9'] = true,
	[':'] = true,
	['A'] = true, ['B'] = true, ['C'] = true, ['D'] = true, ['E'] = true, ['F'] = true, ['G'] = true,
	['H'] = true, ['I'] = true, ['J'] = true, ['K'] = true, ['L'] = true, ['M'] = true, ['N'] = true,
	['O'] = true, ['P'] = true, ['Q'] = true, ['R'] = true, ['S'] = true, ['T'] = true, ['U'] = true,
	['V'] = true, ['W'] = true, ['X'] = true, ['Y'] = true, ['Z'] = true,
	['_'] = true,
	['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true, ['f'] = true, ['g'] = true,
	['h'] = true, ['i'] = true, ['j'] = true, ['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true,
	['o'] = true, ['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = true, ['u'] = true,
	['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true, ['z'] = true,
};

// lookup table for r_name_validate_dash: true = dash-like (replace with _)
static const bool dash_char[256] = {
	['!'] = true, ['"'] = true, ['$'] = true, ['%'] = true, ['('] = true, [')'] = true,
	[','] = true, ['-'] = true, ['/'] = true, [';'] = true, ['<'] = true, ['>'] = true,
	['?'] = true, ['@'] = true, ['['] = true, ['\\'] = true, [']'] = true, ['_'] = true,
	['`'] = true, ['~'] = true, [' '] = true,
};

// lookup table for shell filter: true = skip char
static const bool shell_skip_char[256] = {
	['\n'] = true, ['\r'] = true, [' '] = true, ['"'] = true, ['='] = true, ['\\'] = true,
};

// used to determine if we want to replace those chars with '_' in r_name_filter()
R_API bool r_name_validate_dash(const char ch) {
	return dash_char[(ut8)ch];
}

R_API bool r_name_validate_char(const char ch) {
	return valid_name_char[(ut8)ch];
}

R_API bool r_name_validate_first(const char ch) {
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
		return true;
	}
	switch (ch) {
	case '_':
	case ':':
		return true;
	}
	return false;
}

R_API bool r_name_check(const char *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (!r_name_validate_first (*s)) {
		return false;
	}
	for (s++; *s; s++) {
		if (!valid_name_char[(ut8)*s]) {
			return false;
		}
	}
	return true;
}

static inline bool is_special_char(char n) {
	const char chars[] = "sbfnrtva";
	return strchr (chars, n);
}

R_API const char *r_name_filter_ro(const char *a) {
	R_RETURN_VAL_IF_FAIL (a, NULL);
	while (*a++ == '_');
	return a - 1;
}

R_API bool r_name_filter(char *s, int maxlen) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	size_t count = 0;
	r_str_trim_head (s);
	bool valid = r_name_validate_first (*s);
	if (!valid) {
		*s = '_';
	}
	for (s++; *s; s++) {
		if (maxlen > 0 && count > maxlen) {
			valid = false;
			*s = 0;
			break;
		}
		if (*s == '\\') {
			valid = false;
			if (is_special_char (s[1])) {
				*s = '_';
			} else {
				r_str_cpy (s, s + 1);
				s--;
			}
		}
		if (!r_name_validate_char (*s)) {
			valid = false;
			if (r_name_validate_dash (*s)) {
				*s = '_';
			} else {
				r_str_cpy (s, s + 1);
				s--;
			}
		}
		count++;
	}
	return valid;
}

R_API char *r_name_filter_dup(const char *name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	char *s = strdup (name);
	r_name_filter (s, -1);
	if (*s) {
		return s;
	}
	free (s);
	return NULL;
}

// filter out shell special chars
R_API char *r_name_filter_shell(const char *s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	char *a = malloc (strlen (s) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*s) {
		switch (*s) {
		case '@':
		case '`':
		case '|':
		case ';':
		case '=':
		case '\n':
			break;
		default:
			*b++ = *s;
			break;
		}
		s++;
	}
	*b = 0;
	return a;
}

R_API char *r_name_filter_quoted_shell(const char *s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	char *a = malloc (strlen (s) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*s) {
		if (!shell_skip_char[(ut8)*s]) {
			*b++ = *s;
		}
		s++;
	}
	*b = 0;
	return a;
}
