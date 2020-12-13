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
	case '/':
	case '@':
	case '`':
	case '"':
	case '\n':
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
	for (;*a; a++) {
		if (r_name_validate_first (*a)) {
			break;
		}
	}
	return a;
}

R_API bool r_name_filter_flag(char *s) {
	char *os = s;
	if (!r_name_validate_first (*s)) {
		return false;
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
	return true;
}

R_API bool r_name_filter(char *name, int maxlen) {
	return r_name_filter_flag (name);
#if 0
	if (r_name_validate_print(*name) && !r_name_validate_first (*name)) {
		// fix test, but the whole thing needs a better validation rule
		*name = ' ';
	}
	size_t i;
	if (!name) {
		return false;
	}
	if (maxlen < 0) {
		maxlen = strlen (name);
	}
	r_str_trim (name);
	char *oname = name;
	for (i = 0; *name; name++, i++) {
		if (maxlen && i > maxlen) {
			*name = '\0';
			break;
		}
		if (!r_name_validate_print (*name)) {
			r_str_cpy (name, name + 1);
			i--;
			continue;
		}
		if (!r_name_validate_char (*name) && *name != '\\') {
			if (i == 0) {
				*name = 0;
				return false;
			}
			*name = ' ';
		}
	}
	while (i > 0) {
		if (*(name - 1) == '\\' && is_special_char (name)) {
			*name = '_';
			*(name - 1) = ' ';
		}
		if (*name == '\\') {
			*name = ' ';
		}
		name--;
		i--;
	}
	if (*name == '\\') {
		*name = ' ';
	}
	r_str_trim (oname);
#if 0
	// trimming trailing underscores
	len = strlen (name);
	for (; len > 0 && *(name + len - 1) == '_'; len--) {
		name[len - 1] = 0;
		;
	}
#endif
	return r_name_check (oname);
#endif
}

R_API char *r_name_filter2(const char *name) {
	size_t i;
	while (!r_name_validate_char (*name)) {
		name++;
	}
	char *res = strdup (name);
	for (i = 0; res[i]; i++) {
		if (!r_name_validate_char (res[i])) {
			res[i] = '_';
		}
	}
	for (i--; i != 0 && res[i] == '_'; i--) {
		res[i] = '\0';
	}
	return res;
}
