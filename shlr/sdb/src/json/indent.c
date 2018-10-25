/* sdb - MIT - Copyright 2012-2018 - pancake */

#include <limits.h>

static void doIndent(int idt, char **o, const char *tab) {
	int i;
	char *x;
	for (i = 0; i < idt; i++) {
		for (x = (char *) tab; *x; x++) {
			*(*o)++ = *x;
		}
	}
}

SDB_API char *sdb_json_indent(const char *s, const char *tab) {
	int idx, indent = 0;
	int instr = 0;
	size_t o_size = 0;
	char *o, *O;
	if (!s) {
		return NULL;
	}

	size_t tab_len = strlen (tab);
	for (idx = 0; s[idx]; idx++) {
		if (o_size > INT_MAX - (indent * tab_len + 2)) {
			return NULL;
		}

		if (s[idx] == '{' || s[idx] == '[') {
			indent++;
			// 2 corresponds to the \n and the parenthesis
			o_size += indent * tab_len + 2;
		} else if (s[idx] == '}' || s[idx] == ']') {
			if (indent > 0) {
				indent--;
			}
			// 2 corresponds to the \n and the parenthesis
			o_size += indent * tab_len + 2;
		} else if (s[idx] == ',') {
			// 2 corresponds to the \n and the ,
			o_size += indent * tab_len + 2;
		} else if (s[idx] == ':') {
			o_size += 2;
		} else {
			o_size++;
		}
	}
	// 2 corresponds to the last \n and \0
	o_size += 2;
	indent = 0;

	O = malloc (o_size + 1);
	if (!O) {
		return NULL;
	}

	for (o = O; *s; s++) {
		if (instr) {
			if (s[0] == '"') {
				instr = 0;
			} else if (s[0] == '\\' && s[1] == '"') {
				*o++ = *s;
			}
			*o++ = *s;
			continue;
		} else {
			if (s[0] == '"') {
				instr = 1;
			}
		}
		if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ') {
			continue;
		}
		switch (*s) {
		case ':':
			*o++ = *s;
			*o++ = ' ';
			break;
		case ',':
			*o++ = *s;
			*o++ = '\n';
			doIndent (indent, &o, tab);
			break;
		case '{':
		case '[':
			*o++ = *s;
			*o++ = (indent != -1)? '\n': ' ';
			indent++;
			doIndent (indent, &o, tab);
			break;
		case '}':
		case ']':
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

// TODO: move to utils?
SDB_API char *sdb_json_unindent(const char *s) {
	int instr = 0;
	int len = strlen (s);
	char *o, *O = malloc (len + 1);
	if (!O) {
		return NULL;
	}
	memset (O, 0, len);
	for (o = O; *s; s++) {
		if (instr) {
			if (s[0] != '"') {
				if (s[0] == '\\' && s[1] == '"') {
					*o++ = *s;
				}
			} else {
				instr = 0;
			}
			*o++ = *s;
			continue;
		} else if (s[0] == '"') {
			instr = 1;
		}
		if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ') {
			continue;
		}
		*o++ = *s;
	}
	*o = 0;
	return O;
}
