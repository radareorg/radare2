/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_util.h>

#define IS_PRINTABLE(x) (x>=' '&&x<='~')

static int r_name_validate_char(const char ch) {
	switch (ch) {
	case '=':
	case '*':
	case '/':
	case '+':
	case '|':
	case '&':
	case ';':
	case ':':
	case '~':
	case '"':
	case '>':
	case '<':
	case '#':
	case '%':
	case '(':
	case ')':
	case '`':
	case '\'':
	case '-':
	case ' ':
	case '\n':
	case '\t':
	case '[':
	case ']':
	case '@':
		return 0;
	default:
		if (((ch >= '0') && (ch <= '9')))
			return R_TRUE;
		if (!IS_PRINTABLE (ch))
			return R_FALSE;
	}
	return R_TRUE;
}

R_API int r_name_check(const char *name) {
	if (!*name)
		return R_FALSE;
	for (;*name!='\0'; name++)
		if (!r_name_validate_char (*name))
			return R_FALSE;
	return R_TRUE;
}

R_API int r_name_filter(char *name, int maxlen) {
	int i;
	char *oname;
	name = oname = r_str_trim (name);
	for (i=0; *name!='\0'; name++, i++) {
		if (maxlen && i>maxlen) {
			*name = '\0';
			break;
		}
		if (!r_name_validate_char (*name)) {
			r_str_ccpy (name, name+1, 0);
			name--;
		}
	}
	return r_name_check (oname);
}
