/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_util.h>

R_API int r_name_validate_char(const char ch) {
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (IS_DIGIT(ch))) {
		return true;
	}
	switch (ch) {
	case ':':
	case '.':
	case '_':
		return true;
	}
	return false;
}

R_API int r_name_check(const char *name) {
	/* Cannot start by number */
	if (!name || !*name || IS_DIGIT (*name)) {
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

static inline bool is_special_char (char *name) {
	const char n = *name;
	return (n == 'b' || n == 'f' || n == 'n' || n == 'r' || n == 't' || n == 'v' || n == 'a');
}

R_API int r_name_filter(char *name, int maxlen) {
	int i;
	size_t len;
	if (!name) {
		return 0;
	}
	if (maxlen < 0) {
		maxlen = strlen (name);
	}
	r_str_trim_head_tail (name);
	char *oname = name;
	for (i = 0; *name; name++, i++) {
		if (maxlen && i > maxlen) {
			*name = '\0';
			break;
		}
		if (!r_name_validate_char (*name) && *name != '\\') {
			*name = '_';
			//		r_str_ccpy (name, name+1, 0);
			//name--;
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
	// trimming trailing and leading underscores
	len = strlen (name);
	for (; len > 0 && *(name + len - 1) == '_'; len--) {
		;
	}
	if (!len) { // name consists only of underscores
		return r_name_check (oname);
	}
	for (i = 0; *(name + i) == '_'; i++, len--) {
		;
	}
	memmove (name, name + i, len);
	*(name + len) = '\0';
	return r_name_check (oname);
}

R_API char *r_name_filter2(const char *name) {
	int i;
	while (!IS_PRINTABLE (*name)) {
		name++;
	}
	char *res = strdup (name);
	for (i = 0; res[i]; i++) {
		if (!r_name_validate_char (res[i])) {
			res[i] = '_';
		}
	}
	return res;
}
