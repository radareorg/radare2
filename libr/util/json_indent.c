/* radare2 (from sdb) - MIT - Copyright 2012-2025 - pancake */

#include <r_util.h>

#define MAX_JSON_INDENT 128

static void doIndent(int idt, char** o, const char *tab) {
	int i;
	char *x;
	for (i = 0; i < idt; i++) {
		for (x = (char*) tab; *x; x++) {
			*(*o)++ = *x;
		}
	}
}

#define EMIT_ESC(s, code) do { \
	if (color) { \
		size_t codelen = strlen (code); \
		memcpy (s, code, codelen); \
		s += codelen; \
	} \
} while (0);

enum {
	JC_FALSE,
	JC_TRUE,
	JC_KEY,
	JC_VAL,
	JC_RESET,
};

static const char *origColors[] = {
	Color_RED,    // JC_FALSE
	Color_GREEN,  // JC_TRUE
	Color_CYAN,   // JC_KEY
	Color_YELLOW, // JC_VAL
	Color_RESET,  // JC_RESET
};
// static const char colors

R_API char* r_print_json_path(const char* s, int pos) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	int indent = 0;
	const char *words[MAX_JSON_INDENT] = { NULL };
	int lengths[MAX_JSON_INDENT] = {0};
	int indexs[MAX_JSON_INDENT] = {0};
	int instr = 0;
	bool isarr = false;
	int arrpos = 0;
	const char *os = s;
	size_t osz = (1 + strlen (s)) * 20;
	if (osz < 1) {
		return NULL;
	}
	const char *str_a = NULL;
	for (; *s; s++) {
		const char s0 = *s;
		if (instr) {
			if (s0 == '"') {
				instr = 0;
				ut64 cur = str_a - os;
				if (cur > pos) {
					break;
				}
				if (indent > 0 && indent < MAX_JSON_INDENT) {
					words[indent - 1] = str_a;
					lengths[indent - 1] = s - str_a;
					indexs[indent - 1] = 0;
				}
			}
			continue;
		}

		if (s0 == '"') {
			instr = 1;
			str_a = s + 1;
		}
		if (s0 == '\n' || s0 == '\r' || s0 == '\t' || s0 == ' ') {
			continue;
		}
		switch (s0) {
		case ':':
			break;
		case ',':
			if (isarr) {
				arrpos ++;
				if (indent < MAX_JSON_INDENT) {
					indexs[indent - 1] = arrpos;
					lengths[indent - 1] = (s - os);
				}
			}
			break;
		case '[':
			isarr = true;
			arrpos = 0;
			// fallthrough
		case '{':
			if (indent > MAX_JSON_INDENT) {
				R_LOG_ERROR ("JSON indentation is too deep");
				indent = 0;
			} else {
				indent++;
			}
			break;
		case ']':
			isarr = false;
			// fallthrough
		case '}':
			if (indent > 0) {
				indent--;
			}
			break;
		}
	}
	int i;
	ut64 opos = 0;
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < MAX_JSON_INDENT && i < indent; i++) {
		if ((int)(size_t)words[i] < MAX_JSON_INDENT) {
			ut64 cur = lengths[i];
			if (cur < opos) {
				continue;
			}
			opos = cur;
			if (cur > pos) {
				break;
			}
			r_strbuf_appendf (sb, "0x%08"PFMT64x"  %d  [%d]\n", cur, i, indexs[i]);
		} else {
			char *a = r_str_ndup (words[i], lengths[i]);
			ut64 cur = words[i] - os - 1;
			if (cur < opos) {
				continue;
			}
			opos = cur;
			if (cur > pos) {
				break;
			}
			char *q = strchr (a, '"');
			if (q) {
				*q = 0;
			}
			r_strbuf_appendf (sb, "0x%08"PFMT64x"  %d  %s\n", cur, i, a);
			free (a);
		}
	}
	char *res = r_strbuf_drain (sb);
	if (R_STR_ISEMPTY (res)) {
		R_FREE (res);
	}
	return res;
}

R_API char* r_print_json_human(const char* s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	int indent = 0;
	const char *tab = "  ";
	const int indentSize = strlen (tab);
	int instr = 0;
	char *o, *tmp;
	size_t osz = (1 + strlen (s)) * 20;
	if (osz < 1) {
		return NULL;
	}
	char *O = malloc (osz);
	if (!O) {
		return NULL;
	}
	char *OE = O + osz;
	for (o = O; *s; s++) {
		char s0 = *s;
		if (o + (indent * indentSize) + 10 > OE) {
			int delta = o - O;
			osz += 0x1000 + (indent * indentSize);
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
			if (s0 == '"') {
				instr = 0;
			} else if (s[0] == '\\' && s[1] == '"') {
				// XXX maybe buggy
				*o++ = *s++;
			}
			if (*s != '"') {
				*o++ = *s;
			}
			continue;
		}
		if (indent <= 0) {
			// non-JSON part
			if (s[0] != '{' && s[0] != '[') {
				*o++ = *s;
				continue;
			}
		}
		s0 = *s;
		if (s0 == '"') {
			instr = 1;
		}
		if (s0 == '\n' || s0 == '\r' || s0 == '\t' || s0 == ' ') {
			continue;
		}
		switch (s0) {
		case ':':
			*o++ = s0;
			*o++ = ' ';
			break;
		case ',':
			*o++ = '\n';
			doIndent (indent - 1, &o, tab);
			break;
		case '{':
		case '[':
			if (indent > 0) {
				*o++ = (indent != -1)? '\n': ' ';
			}
			if (indent > MAX_JSON_INDENT) {
				R_LOG_ERROR ("JSON indentation is too deep");
				indent = 0;
			} else {
				indent++;
			}
			doIndent (indent - 1, &o, tab);
			break;
		case '}':
		case ']':
			if (indent > 0) {
				indent--;
			}
			doIndent (indent - 1, &o, tab);
			*o++ = s0;
			break;
		default:
			if (!instr) {
				*o++ = s0;
			}
		}
	}
	*o = 0;
	return O;
}

R_API char* r_print_json_indent(const char* s, bool color, const char* tab, const char **palette) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	int indent = 0;
	const int indentSize = strlen (tab);
	int instr = 0;
	bool isValue = false;
	char *o, *tmp;
	const char **colors = palette ? palette: origColors;
	size_t osz = (1 + strlen (s)) * 20;
	if (osz < 1) {
		return NULL;
	}

	char *O = malloc (osz);
	if (!O) {
		return NULL;
	}
	char *OE = O + osz;
	for (o = O; *s; s++) {
		if (o + (indent * indentSize) + 10 > OE) {
			int delta = o - O;
			osz += 0x1000 + (indent * indentSize);
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
				*o++ = *s++;
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
			// non-JSON part, skip it
			if (s[0] != '{' && s[0] != '[') {
				if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ') {
					*o++ = *s;
				}
				continue;
			}
		}

		const char s0 = *s;
		if (s0 == '"') {
			instr = 1;
		}
		if (s0 == '\n' || s0 == '\r' || s0 == '\t' || s0 == ' ' || !IS_PRINTABLE (s0)) {
			continue;
		}
		switch (s0) {
		case ':':
			*o++ = s0;
			*o++ = ' ';
			s = r_str_trim_head_ro (s + 1);
			if (r_str_startswith (s, "true")) {
				EMIT_ESC (o, colors[JC_TRUE]);
			} else if (r_str_startswith (s, "false")) {
				EMIT_ESC (o, colors[JC_FALSE]);
			}
			s--;
			isValue = true;
			break;
		case ',':
			EMIT_ESC (o, colors[JC_RESET]);
			*o++ = s0;
			*o++ = '\n';
			isValue = false;
			doIndent (indent, &o, tab);
			break;
		case '{':
		case '[':
			isValue = false;
			*o++ = s0;
			*o++ = (indent != -1)? '\n': ' ';
			if (indent > MAX_JSON_INDENT) {
				R_LOG_ERROR ("JSON indentation is too deep");
				indent = 0;
			} else {
				indent++;
			}
			doIndent (indent, &o, tab);
			break;
		case '}':
		case ']':
			EMIT_ESC (o, colors[JC_RESET]);
			isValue = false;
			*o++ = '\n';
			if (indent > 0) {
				indent--;
			}
			doIndent (indent, &o, tab);
			*o++ = *s;
			break;
		default:
			*o++ = s0;
			break;
		}
	}
	*o = 0;
	return O;
}

#undef EMIT_ESC
