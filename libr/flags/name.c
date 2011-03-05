/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_flags.h>
#include <r_util.h>

#define IS_PRINTABLE(x) (x>=' '&&x<='~')

static int r_flag_name_validate_char(const char ch) {
	switch (ch) {
	case '*':
	case '/':
	case '+':
	case '|':
	case '&':
	case ';':
	case ':':
	case '>':
	case '<':
	case '"':
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
			return 1;
		if (!IS_PRINTABLE (ch))
			return 0;
	}
	return 1;
}

R_API int r_flag_name_check(const char *name) {
	if (name[0]=='\0')
		return 0;
	for (;*name!='\0'; name++)
		if (!r_flag_name_validate_char (*name))
			return 0;
	return 1;
}

R_API int r_flag_name_filter(char *name) {
	int i;
	char *oname;
	name = oname = r_str_trim (name);
	for (i=0;*name!='\0'; name = name +1,i++) {
		if (i>R_FLAG_NAME_SIZE) {
			name[0] = '\0';
			break;
		}
		if (!r_flag_name_validate_char (*name)) {
			strcpy (name, name+1);
			name = name -1;
		}
	}
	return r_flag_name_check (oname);
}
