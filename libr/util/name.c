/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <r_util.h>

/* Validate if char is printable , why not use ISPRINTABLE() ?? */
R_API bool r_name_validate_print(const char ch) {
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || IS_DIGIT (ch)) {
		return true;
	}
	switch (ch) {
	case '<':
	case '>':
	case '$':
	case '%':
	case '@':
	case ' ':
	case '.':
	case ',':
	case ':':
	case '_':
		return true;
	case '\b':
	case '\t':
	case '\n':
	case '\r':
		// must be replaced with ' ' and trimmed later
		return false;
	}
	return false;
}

// used to determine if we want to replace those chars with '_' in r_name_filter()
R_API bool r_name_validate_dash(const char ch) {
	switch (ch) {
	case ' ':
	case '-':
	case '_':
	case '/':
	case '(':
	case ')':
	case '[':
	case ']':
	case '<':
	case '>':
	case '!':
	case '?':
	case '$':
	case ';':
	case '%':
	case '@':
	case '`':
	case ',':
	case '"':
		return true;
	}
	return false;
}

R_API bool r_name_validate_char(const char ch) {
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || IS_DIGIT (ch)) {
		return true;
	}
	switch (ch) {
	case '.':
	case ':':
	case '_':
		return true;
	}
	return false;
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
	if (!r_name_validate_first (*s)) {
		return false;
	}
	for (s++; *s; s++) {
		if (!r_name_validate_char (*s)) {
			return false;
		}
	}
	return true;
}

static inline bool is_special_char(char n) {
	return (n == 'b' || n == 'f' || n == 'n' || n == 'r' || n == 't' || n == 'v' || n == 'a');
}

R_API const char *r_name_filter_ro(const char *a) {
	while (*a++ == '_');
	return a - 1;
}


R_API bool r_name_filter(char *s, int maxlen) {
	// if maxlen == -1 : R_FLAG_NAME_SIZE
	// maxlen is ignored, the function signature must change
	if (maxlen > 0) {
		int slen = strlen (s);
		if (slen > maxlen) {
			s[maxlen] = 0;
		}
	}
	char *os = s;
	if (!r_name_validate_first (*s)) {
		if (r_name_validate_dash (*s)) {
			*s = '_';
		} else {
			return false;
		}
	}
	for (s++; *s; s++) {
		if (*s == '\\') {
			if (is_special_char (s[1])) {
				r_str_cpy (s, s + 2);
				s--;
			} else {
				r_str_cpy (s, s + 1);
				s--;
			}
		}
		if (!r_name_validate_char (*s)) {
			if (r_name_validate_dash (*s)) {
				*s = '_';
			} else {
				r_str_cpy (s, s + 1);
				s--;
			}
		}
	}
	r_str_trim (os);
	return r_name_check (os);
}

R_API char *r_name_filter2(const char *name) {
	char *s = strdup (name);
	r_name_filter (s, -1);
	return s;
}
