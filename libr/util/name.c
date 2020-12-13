/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <r_util.h>

R_API bool r_name_validate_char(const char ch) {
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || IS_DIGIT (ch)) {
		return true;
	}
	return r_name_validate_special (ch) == 1;
}

R_API int r_name_validate_special(const char ch) {
	switch (ch) {
	case ':':
	case '.':
	case '_':
		return 1;
	case ' ':
	case '$':
	case '<':
	case '>':
		return 2;
	}
	return 0;
}

R_API bool r_name_check(const char *name) {
	r_return_val_if_fail (name, false);
	/* Cannot start by number */
	if (!*name || IS_DIGIT (*name) || *name == '$') {
		return false;
	}
	/* Cannot contain non-alphanumeric chars + [:._] */
	for (; *name != '\0'; name++) {
		if (!r_name_validate_char (*name)) {
			return false;
		}
	}
	return true;
}

static inline bool is_special_char(char *name) {
	const char n = *name;
	return (n == 'b' || n == 'f' || n == 'n' || n == 'r' || n == 't' || n == 'v' || n == 'a');
}

R_API const char *r_name_filter_ro(const char *a) {
	while (*a && r_name_validate_special (*a)) {
		a++;
	}
	return a;
}

R_API bool r_name_filter(char *name, int maxlen) {
	if (*name == '<') {
		// fix test, but the whole thing needs a better validation rule
		r_str_cpy (name, name + 1);
	}
	size_t i, len;
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
		if (!r_name_validate_char (*name) && *name != '\\') {
			if (i == 0) {
				*name = 0;
				return false;
			}
			*name = '_';
		}
	}
	while (i > 0) {
		if (*(name - 1) == '\\' && is_special_char (name)) {
			*name = '_';
			*(name - 1) = '_';
		}
		if (*name == '\\') {
			*name = '_';
		}
		name--;
		i--;
	}
	if (*name == '\\') {
		*name = '_';
	}
	// trimming trailing underscores
	len = strlen (name);
	for (; len > 0 && *(name + len - 1) == '_'; len--) {
		name[len - 1] = 0;
		;
	}
	return r_name_check (oname);
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
