/* radare2 (from sdb) - MIT - Copyright 2012-2017 - pancake */

#include <r_util.h>
#include <r_print.h>


static void doIndent(int idt, char** o, const char *tab) {
	int i;
	char *x;
	for (i = 0; i < idt; i++) {
		for (x = (char*) tab; *x; x++) {
			*(*o)++ = *x;
		}
	}
}

R_API char* r_print_json_indent(const char* s, bool color, const char* tab) {
	if (!color) {
		return sdb_json_indent (s, tab);
	}
	int indent = 0;
	int instr = 0;
	bool isValue = false;
	int osz;
	char* o, * O, * OE, * tmp;
	if (!s) {
		return NULL;
	}
	osz = (1 + strlen (s)) * 20;
	if (osz < 1) {
		return NULL;
	}
	O = malloc (osz);
	if (!O) {
		return NULL;
	}
	OE = O + osz;
	for (o = O; *s; s++) {
		if (o + indent + 10 > OE) {
			int delta = o - O;
			osz += 0x1000 + indent;
			if (osz < 1) {
				free (O);
				return NULL;
			}
			tmp = realloc (O, osz);
			if (!tmp) {
				free (O);
				return NULL;
			}
			O = tmp;
			OE = tmp + osz;
			o = O + delta;
		}
		if (instr) {
			if (s[0] == '"') {
				instr = 0;
			} else if (s[0] == '\\' && s[1] == '"') {
				*o++ = *s;
			}
			if (instr) {
				*o++ = 0x1b;
				*o++ = '[';
				if (isValue) {
					*o++ = '3';
					*o++ = '4';
				} else {
					*o++ = '3';
					*o++ = '3';
				}
				*o++ = 'm';
			} else {
				*o++ = 0x1b;
				*o++ = '[';
				*o++ = '0';
				*o++ = 'm';
			}
			*o++ = *s;
			continue;
		}
		if (s[0] == '"') {
			instr = 1;
		}
		if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ') {
			continue;
		}
		switch (*s) {
		case ':':
			*o++ = *s;
			*o++ = ' ';
			if (!strncmp (s + 1, "true", 4)) {
				*o++ = 0x1b;
				*o++ = '[';
				*o++ = '3';
				*o++ = '2';
				*o++ = 'm';
			} else if (!strncmp (s + 1, "false", 5)) {
				*o++ = 0x1b;
				*o++ = '[';
				*o++ = '3';
				*o++ = '1';
				*o++ = 'm';
			}
			isValue = true;
			break;
		case ',':
			*o++ = 0x1b;
			*o++ = '[';
			*o++ = '0';
			*o++ = 'm';
			*o++ = *s;
			*o++ = '\n';
			isValue = false;
			doIndent (indent, &o, tab);
			break;
		case '{':
		case '[':
			isValue = false;
			*o++ = *s;
			*o++ = (indent != -1)? '\n': ' ';
			indent++;
			doIndent (indent, &o, tab);
			break;
		case '}':
		case ']':
			*o++ = 0x1b;
			*o++ = '[';
			*o++ = '0';
			*o++ = 'm';
			isValue = false;
			*o++ = '\n';
			indent--;
			doIndent (indent, &o, tab);
			*o++ = *s;
			break;
		default:
			*o++ = *s;
		}
	}
	*o++ = '\n';
	*o = 0;
	return O;
}
