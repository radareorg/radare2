/* radare - LGPL - Copyright 2009-2021 - pancake */

#include <r_util.h>

#define FAST_FILTER 1

/* Validate if char is printable , why not use ISPRINTABLE() ?? */
R_API bool r_name_validate_print(const char ch) {
	// TODO: support utf8
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || IS_DIGIT (ch)) {
		return true;
	}
	switch (ch) {
	case '(':
	case ')':
	case '[':
	case ']':
	case '<':
	case '+':
	case '-':
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
	case '\\':
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
	return (ch == '.' || ch == ':' || ch == '_');
	// return (ch == ';' || ch == '.' || ch == ':' || ch == '_');
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
	return (n == 's' || n == 'b' || n == 'f' || n == 'n' || n == 'r' || n == 't' || n == 'v' || n == 'a');
}

R_API const char *r_name_filter_ro(const char *a) {
	if (!a) {
		return NULL;
	}
	while (*a++ == '_');
	return a - 1;
}

// filter string for printing purposes
R_API bool r_name_filter_print(char *s) {
	char *es = s + strlen (s);
	char *os = s;
	while (*s && s < es) {
		int us = r_utf8_size ((const ut8*)s);
		if (us > 1) {
			s += us;	
			continue;
		}
		if (!r_name_validate_print (*s)) {
			r_str_cpy (s, s + 1);
		}
		s++;
	}
	return os;
}

R_API bool r_name_filter(char *s, int maxlen) {
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	// if maxlen == -1 : R_FLAG_NAME_SIZE
	// maxlen is ignored, the function signature must change
	// char *os = s;
	size_t count = 0;
	r_str_trim_head (s);
	if (!r_name_validate_first (*s)) {
		*s = '_';
	}
#if 0
		while (*s) {
			if (maxlen > 0 && count > maxlen) {
				*s = 0;
				break;
			}
			if (r_name_validate_char (*s)) {
				break;
			}
			if (r_name_validate_dash (*s)) {
				break;
			}
			r_str_cpy (s, s + 1);
			count++;
		}
	}
#endif
	for (s++; *s; s++) {
		if (maxlen > 0 && count > maxlen) {
			*s = 0;
			break;
		}
		if (*s == '\\') {
			if (is_special_char (s[1])) {
				*s = '_';
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
		count++;
	}
#if FAST_FILTER
	// that flag should be trimmed and checked already
	// we dont want to iterate over it again
	return true;
#else
	r_str_trim (os);
	return r_name_check (os);
#endif
}

R_API char *r_name_filter_dup(const char *name) {
	char *s = strdup (name);
	r_name_filter (s, -1);
	return s;
}
