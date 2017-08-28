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

#define EMIT_ESC(s, code) do {			\
	if (color) {				\
		const char *p = code;			\
		while (*p) {			\
			*s++ = *p++;		\
		}				\
	}					\
} while (0);

enum {
	JC_FALSE, // 31m
	JC_TRUE, // 32m
	JC_KEY, // 33m
	JC_VAL, // 34m
	JC_RESET,
};

static const char *origColors[] = {
	"\x1b[31m",
	"\x1b[32m",
	"\x1b[33m",
	"\x1b[34m",
	"\x1b[0m",
};
// static const char colors

R_API char* r_print_json_indent(const char* s, bool color, const char* tab, const char **palette) {
	int indent = 0;
	int instr = 0;
	bool isValue = false;
	char *o, *OE, *tmp;
	if (!s) {
		return NULL;
	}
	const char **colors = palette ? palette: origColors;
	int osz = (1 + strlen (s)) * 20;
	if (osz < 1) {
		return NULL;
	}

	char *O = malloc (osz);
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
				if (isValue) {
					// TODO: do not emit color in every char
					EMIT_ESC (o, colors[JC_VAL]);
				} else {
					EMIT_ESC (o, colors[JC_KEY]);
				}
			} else {
				EMIT_ESC (o, colors[JC_RESET]);
			}
			*o++ = *s;
			continue;
		}
		if (indent <= 0) {
			// non-JSON part
			if (s[0] != '{' && s[0] != '[') {
				*o++ = *s;
				continue;
			}
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
				EMIT_ESC (o, colors[JC_TRUE]);
			} else if (!strncmp (s + 1, "false", 5)) {
				EMIT_ESC (o, colors[JC_FALSE]);
			}
			isValue = true;
			break;
		case ',':
			EMIT_ESC (o, colors[JC_RESET]);
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
			EMIT_ESC (o, colors[JC_RESET]);
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
	*o = 0;
	return O;
}

#undef EMIT_ESC
