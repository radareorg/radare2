/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_util.h>

/* Validate if char is printable , why not use ISPRINTABLE() ?? */
R_API bool r_name_validate_print(const char ch) {
	// TODO: support utf8
	if (isalpha (ch & 0xff) || isdigit (ch & 0xff)) {
		return true;
	}
	const char chars[] = "()[]<>+-$%@ .,:_";
	if (strchr (chars, ch)) {
		return true;
	}
	return false;
}

// used to determine if we want to replace those chars with '_' in r_name_filter()
R_API bool r_name_validate_dash(const char ch) {
	const char chars[] = " -_/\\()~[]<>!?$;%@`,\"";
	return strchr (chars, ch);
}

R_API bool r_name_validate_char(const char ch) {
	if (isalpha (ch & 0xff) || isdigit (ch & 0xff)) {
		return true;
	}
	return (ch == '.' || ch == ':' || ch == '_');
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
		if (!r_name_validate_char (*s)) {
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

// filter string for printing purposes
R_API bool r_name_filter_print(char *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	char *es = s + strlen (s);
	bool valid = true;
	while (*s && s < es) {
		int us = r_utf8_size ((const ut8*)s);
		if (us > 1) {
			s += us;
			continue;
		}
		if (!r_name_validate_print (*s)) {
			r_str_cpy (s, s + 1);
			valid = false;
		}
		s++;
	}
	return valid;
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
	return s;
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
		switch (*s) {
		case ' ':
		case '=':
		case '"':
		case '\\':
		case '\r':
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
