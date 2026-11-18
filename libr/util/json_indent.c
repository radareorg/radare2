/* radare2 (from sdb) - MIT - Copyright 2012-2023 - pancake */

#include <r_util.h>

#define MAX_JSON_INDENT 128

// "\n" followed by the tab repeated for the deepest indentation level
static char *indent_string(const char *tab) {
	RStrBuf *sb = r_strbuf_new ("\n");
	int i;
	for (i = 0; i <= MAX_JSON_INDENT; i++) {
		r_strbuf_append (sb, tab);
	}
	return r_strbuf_drain (sb);
}

static void doIndent(RStrBuf *sb, const char *ind, size_t tabsz, int idt, bool newline) {
	const size_t n = R_MIN (R_MAX (idt, 0), MAX_JSON_INDENT + 1) * tabsz;
	r_strbuf_append_n (sb, newline? ind: ind + 1, n + newline);
}

// returns the closing quote or the terminating NUL of the string opened at s
static const char *json_string_end(const char *s) {
	for (s++; *s && *s != '"'; s++) {
		if (*s == '\\' && s[1]) {
			s++;
		}
	}
	return s;
}

static size_t json_literal_len(const char *s) {
	size_t n = 0;
	while (IS_PRINTABLE (s[n]) && !strchr ("\"{}[],: ", s[n])) {
		n++;
	}
	return n;
}

#define EMIT_ESC(sb, code) \
	do { \
		if (color) { \
			r_strbuf_append (sb, code); \
		} \
	} while (0)

enum {
	JC_FALSE,
	JC_TRUE,
	JC_KEY,
	JC_VAL,
	JC_RESET,
};

static const char *origColors[] = {
	Color_RED, // JC_FALSE
	Color_GREEN, // JC_TRUE
	Color_CYAN, // JC_KEY
	Color_YELLOW, // JC_VAL
	Color_RESET, // JC_RESET
};
// static const char colors

R_API char *r_print_json_path(const char *s, int pos) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	int indent = 0;
	const char *words[MAX_JSON_INDENT] = { NULL };
	int lengths[MAX_JSON_INDENT] = { 0 };
	int indexs[MAX_JSON_INDENT] = { 0 };
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
				arrpos++;
				if (indent > 0 && indent < MAX_JSON_INDENT) {
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
			indent--;
			break;
		}
	}
	int i;
	ut64 opos = 0;
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < MAX_JSON_INDENT && i < indent; i++) {
		if ((int) (size_t)words[i] < MAX_JSON_INDENT) {
			ut64 cur = lengths[i];
			if (cur < opos) {
				continue;
			}
			opos = cur;
			if (cur > pos) {
				break;
			}
			r_strbuf_appendf (sb, "0x%08" PFMT64x "  %d  [%d]\n", cur, i, indexs[i]);
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
			r_strbuf_appendf (sb, "0x%08" PFMT64x "  %d  %s\n", cur, i, a);
			free (a);
		}
	}
	char *res = r_strbuf_drain (sb);
	if (R_STR_ISEMPTY (res)) {
		R_FREE (res);
	}
	return res;
}

R_API char *r_print_json_human(const char *s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	const char *tab = "  ";
	char *ind = indent_string (tab);
	const size_t tabsz = strlen (tab);
	int indent = 0;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_reserve (sb, strlen (s) * 2);
	for (; *s; s++) {
		const char s0 = *s;
		if (indent <= 0 && s0 != '{' && s0 != '[') {
			// non-JSON part
			r_strbuf_append_n (sb, s, 1);
			continue;
		}
		if (!IS_PRINTABLE (s0) || s0 == ' ') {
			continue;
		}
		switch (s0) {
		case '"':
			{
				const char *end = json_string_end (s);
				r_strbuf_append_n (sb, s + 1, end - s - 1);
				s = *end? end: end - 1;
			}
			break;
		case ':':
			r_strbuf_append (sb, ": ");
			break;
		case ',':
			doIndent (sb, ind, tabsz, indent - 1, true);
			break;
		case '{':
		case '[':
			{
				const bool nested = indent > 0;
				if (indent > MAX_JSON_INDENT) {
					R_LOG_ERROR ("JSON indentation is too deep");
					indent = 0;
				} else {
					indent++;
				}
				doIndent (sb, ind, tabsz, indent - 1, nested);
			}
			break;
		case '}':
		case ']':
			indent--;
			doIndent (sb, ind, tabsz, indent - 1, false);
			break;
		default:
			{
				const size_t n = json_literal_len (s);
				r_strbuf_append_n (sb, s, n);
				s += n - 1;
			}
			break;
		}
	}
	free (ind);
	return r_strbuf_drain (sb);
}

R_API char *r_print_json_indent(const char *s, bool color, const char *tab, const char **palette) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	const char **colors = palette? palette: origColors;
	char *ind = indent_string (tab);
	const size_t tabsz = strlen (tab);
	int indent = 0;
	bool isValue = false;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_reserve (sb, strlen (s) * 2);
	for (; *s; s++) {
		const char s0 = *s;
		const bool isSpace = s0 == '\n' || s0 == '\r' || s0 == '\t' || s0 == ' ';
		if (indent <= 0 && s0 != '{' && s0 != '[') {
			// non-JSON part, skip it
			if (isSpace) {
				r_strbuf_append_n (sb, s, 1);
			}
			continue;
		}
		if (isSpace || !IS_PRINTABLE (s0)) {
			continue;
		}
		switch (s0) {
		case '"':
			{
				const char *end = json_string_end (s);
				EMIT_ESC (sb, colors[isValue? JC_VAL: JC_KEY]);
				r_strbuf_append_n (sb, s, end - s + (*end? 1: 0));
				EMIT_ESC (sb, colors[JC_RESET]);
				s = *end? end: end - 1;
			}
			break;
		case ':':
			r_strbuf_append (sb, ": ");
			s = r_str_trim_head_ro (s + 1);
			if (r_str_startswith (s, "true")) {
				EMIT_ESC (sb, colors[JC_TRUE]);
			} else if (r_str_startswith (s, "false")) {
				EMIT_ESC (sb, colors[JC_FALSE]);
			}
			s--;
			isValue = true;
			break;
		case ',':
			EMIT_ESC (sb, colors[JC_RESET]);
			r_strbuf_append_n (sb, s, 1);
			isValue = false;
			doIndent (sb, ind, tabsz, indent, true);
			break;
		case '{':
		case '[':
			isValue = false;
			r_strbuf_append_n (sb, s, 1);
			if (indent > MAX_JSON_INDENT) {
				R_LOG_ERROR ("JSON indentation is too deep");
				indent = 0;
			} else {
				indent++;
			}
			doIndent (sb, ind, tabsz, indent, true);
			break;
		case '}':
		case ']':
			EMIT_ESC (sb, colors[JC_RESET]);
			isValue = false;
			indent--;
			doIndent (sb, ind, tabsz, indent, true);
			r_strbuf_append_n (sb, s, 1);
			break;
		default:
			{
				const size_t n = json_literal_len (s);
				r_strbuf_append_n (sb, s, n);
				s += n - 1;
			}
			break;
		}
	}
	free (ind);
	return r_strbuf_drain (sb);
}

#undef EMIT_ESC
