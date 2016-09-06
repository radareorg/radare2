/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_util.h>

R_API int r_name_validate_char(const char ch) {
	if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))
		return true;
	switch (ch) {
	case ':':
	case '.':
	case '_':
		return true;
	}
	return false;
}

R_API int r_name_check(const char *name) {
	if (!name || !*name)
		return false;
	/* Cannot start by number */
	if (*name >= '0' && *name <= '9')
		return false;
	/* Cannot contain non-alphanumeric chars + [:._] */
	for (; *name != '\0'; name++)
		if (!r_name_validate_char (*name))
			return false;
	return true;
}

R_API int r_name_filter(char *name, int maxlen) {
	int i;
	char *oname;
	if (!name) return 0;
	if (maxlen < 0) {
		maxlen = strlen (name);
	}
	name = oname = r_str_trim_head_tail (name);
	for (i = 0; *name; name++, i++) {
		if (maxlen && i > maxlen) {
			*name = '\0';
			break;
		}
		if (!r_name_validate_char (*name)) {
			*name = '_';
			//		r_str_ccpy (name, name+1, 0);
			//name--;
		}
	}
	return r_name_check (oname);
}

R_API char *r_name_filter2(const char *name) {
	int i;
	char *res;
	while (!IS_PRINTABLE (*name))
		name++;
	res = strdup (name);
	for (i = 0; res[i]; i++) {
		if (!r_name_validate_char (res[i])) {
			res[i] = '_';
		}
	}
	return res;
}
