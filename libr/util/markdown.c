/* radare - LGPL - Copyright 2007-2026 - pancake */

#include <r_bin.h>
#include <r_util/r_table.h>
#include <r_util/r_print.h>
#include <ctype.h>

enum {
	MD_BOLD = 1,
	MD_ITALIC = 2,
	MD_STRIKE = 4,
	MD_CODE = 8,
	MD_BLUE = 16,
};

static void md_style(RStrBuf *sb, int style) {
	if (style & MD_BOLD) {
		r_strbuf_append (sb, Color_BOLD);
	}
	if (style & MD_ITALIC) {
		r_strbuf_append (sb, Color_ITALIC);
	}
	if (style & MD_STRIKE) {
		r_strbuf_append (sb, Color_STRIKE);
	}
	if (style & MD_BLUE) {
		r_strbuf_append (sb, Color_BBLUE);
	}
	if (style & MD_CODE) {
		r_strbuf_append (sb, "\x1b[48;5;234m" Color_WHITE);
	}
}

static char *md_wrap_text(const char *text, int width) {
	RStrBuf *normalized = r_strbuf_new ("");
	const char *p = text;
	const char *end = text + strlen (text);
	while (p < end) {
		int len = R_MAX (1, r_utf8_decode ((const ut8 *)p, R_MIN (end - p, 4), NULL));
		char rune[5] = {0};
		memcpy (rune, p, len);
		r_strbuf_append (normalized, width == 1 && r_str_len_utf8 (rune) > 1? "?": rune);
		p += len;
	}
	char *wrapped = r_str_wrap (r_strbuf_get (normalized), width);
	r_strbuf_free (normalized);
	if (!wrapped) {
		return NULL;
	}
	RStrBuf *out = r_strbuf_new ("");
	int style = 0;
	p = wrapped;
	while (*p) {
		if (*p == '\n') {
			if (style) {
				r_strbuf_append (out, Color_RESET);
			}
			r_strbuf_append (out, "\n");
			md_style (out, style);
			p++;
			continue;
		}
		if (*p == '\x1b') {
			static const struct {
				const char *code;
				int set;
				int clear;
			} attributes[] = {
				{ Color_RESET, 0, -1 },
				{ Color_BOLD, MD_BOLD, 0 },
				{ Color_BOLD_RESET, 0, MD_BOLD },
				{ Color_ITALIC, MD_ITALIC, 0 },
				{ Color_ITALIC_RESET, 0, MD_ITALIC },
				{ Color_STRIKE, MD_STRIKE, 0 },
				{ Color_STRIKE_RESET, 0, MD_STRIKE },
				{ Color_BBLUE, MD_BLUE, 0 },
				{ "\x1b[48;5;234m", MD_CODE, 0 },
				{ Color_RESET_BG, 0, MD_CODE },
			};
			size_t i;
			for (i = 0; i < R_ARRAY_SIZE (attributes); i++) {
				if (r_str_startswith (p, attributes[i].code)) {
					style = (style & ~attributes[i].clear) | attributes[i].set;
					break;
				}
			}
		}
		r_strbuf_append_n (out, p++, 1);
	}
	if (style) {
		r_strbuf_append (out, Color_RESET);
	}
	free (wrapped);
	return r_strbuf_drain (out);
}

static void md_append_wrapped(RStrBuf *out, const char *text, int width, const char *prefix, const char *continuation, bool color, bool newline) {
	int prefix_width = R_MAX (r_str_len_utf8_ansi (prefix), r_str_len_utf8_ansi (continuation));
	while (prefix_width >= width - 1 && *prefix == ' ' && *continuation == ' ') {
		prefix++;
		continuation++;
		prefix_width--;
	}
	if (prefix_width >= width - 1) {
		prefix = continuation = "";
		prefix_width = 0;
	}
	char *wrapped = md_wrap_text (text, width - prefix_width);
	if (!wrapped) {
		return;
	}
	char *row = wrapped;
	for (;;) {
		char *eol = strchr (row, '\n');
		if (eol) {
			*eol = 0;
		}
		r_strbuf_append (out, prefix);
		r_strbuf_append (out, row);
		if (color) {
			r_strbuf_append (out, Color_RESET);
		}
		if (eol || newline) {
			r_strbuf_append (out, "\n");
		}
		if (!eol) {
			break;
		}
		row = eol + 1;
		prefix = continuation;
	}
	free (wrapped);
}

static void fill_line(RStrBuf *sb, int maxcol) {
	if (maxcol > 0) {
		r_strbuf_appendf (sb, "%*s", maxcol, "");
	}
	r_strbuf_append (sb, Color_RESET_BG Color_RESET "\n");
}

typedef enum {
	MD_CODE_PLAIN,
	MD_CODE_SYNTAX,
	MD_CODE_DIFF,
} MDCodeKind;

static MDCodeKind md_code_kind(const char *info) {
	info = r_str_trim_head_ro (info);
	size_t len = strcspn (info, " \t");
	if ((len == 4 && !r_str_ncasecmp (info, "diff", len))
		|| (len == 5 && !r_str_ncasecmp (info, "patch", len))) {
		return MD_CODE_DIFF;
	}
	if ((len == 4 && !r_str_ncasecmp (info, "text", len))
		|| (len == 5 && !r_str_ncasecmp (info, "plain", len))
		|| (len == 9 && !r_str_ncasecmp (info, "plaintext", len))) {
		return MD_CODE_PLAIN;
	}
	return MD_CODE_SYNTAX;
}

static int md_code_color(const char *text, const char **foreground) {
	static const char *colors[] = {
		Color_YELLOW, Color_CYAN, Color_GREEN, Color_BLUE,
		Color_MAGENTA, Color_RED, Color_RESET,
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (colors); i++) {
		if (r_str_startswith (text, colors[i])) {
			*foreground = !strcmp (colors[i], Color_RESET)? Color_WHITE: colors[i];
			return strlen (colors[i]);
		}
	}
	return 0;
}

static void md_code_row_start(RStrBuf *sb, bool usecolor, int indent, int padding, const char *background, const char *foreground) {
	r_strbuf_appendf (sb, "%*s", indent, "");
	if (usecolor) {
		r_strbuf_append (sb, background);
		r_strbuf_append (sb, Color_WHITE);
	}
	r_strbuf_appendf (sb, "%*s", padding, "");
	if (usecolor && strcmp (foreground, Color_WHITE)) {
		r_strbuf_append (sb, foreground);
	}
}

static void md_code_row_end(RStrBuf *sb, bool usecolor, int padding) {
	if (usecolor) {
		r_strbuf_appendf (sb, "%*s", padding, "");
		r_strbuf_append (sb, Color_RESET_BG Color_RESET);
	}
	r_strbuf_append (sb, "\n");
}

static int md_code_width(const char *text, int max_width) {
	const char *end = text + strlen (text);
	int width = 1;
	int col = 0;
	while (text < end) {
		int len = R_MAX (1, r_utf8_decode ((const ut8 *)text, R_MIN (end - text, 4), NULL));
		char rune[5] = {0};
		memcpy (rune, text, len);
		if (*text == '\n') {
			col = 0;
		} else if (*text != '\r') {
			int columns = *text == '\t'? 2: r_str_len_utf8 (rune);
			if (columns >= max_width - col) {
				return max_width;
			}
			col += columns;
			width = R_MAX (width, col);
		}
		text += len;
	}
	return width;
}

static const char *md_render_code_line(const char *b, RStrBuf *sb, int content_width, int indent, int padding, bool usecolor, bool highlight, const char *background, const char **foreground) {
	const char *end = strchr (b, '\n');
	if (!end) {
		end = b + strlen (b);
	}
	int col = 0;
	md_code_row_start (sb, usecolor, indent, padding, background, *foreground);
	while (b < end) {
		if (highlight && *b == '\x1b') {
			int len = md_code_color (b, foreground);
			if (len) {
				r_strbuf_append (sb, *foreground);
				b += len;
				continue;
			}
		}
		if (*b == '\r') {
			b++;
			continue;
		}
		int len = r_utf8_decode ((const ut8 *)b, R_MIN (end - b, 4), NULL);
		len = R_MAX (len, 1);
		char text[5] = {0};
		memcpy (text, b, len);
		int columns = r_str_len_utf8 (text);
		int repeat = 1;
		if (*b == '\t') {
			text[0] = ' ';
			columns = 1;
			repeat = 2;
		} else if (columns > content_width) {
			text[0] = '?';
			text[1] = 0;
			columns = 1;
		}
		while (repeat-- > 0) {
			if (col + columns > content_width) {
				md_code_row_end (sb, usecolor, content_width - col + padding);
				md_code_row_start (sb, usecolor, indent, padding, background, *foreground);
				col = 0;
			}
			r_strbuf_append (sb, text);
			col += columns;
		}
		b += len;
	}
	md_code_row_end (sb, usecolor, content_width - col + padding);
	return *end? end + 1: end;
}

static void md_render_code(RStrBuf *code, RStrBuf *out, int width, bool usecolor, bool highlight, MDCodeKind kind, bool fenced) {
	if (r_strbuf_is_empty (code)) {
		return;
	}
	highlight &= usecolor;
	const char *text = r_strbuf_get (code);
	const int indent = width > 5? 2: 0;
	const int padding = width > 3? 1: 0;
	int content_width = width - indent - 2 * padding;
	if (usecolor) {
		content_width = md_code_width (text, content_width);
	}
	char *colored = highlight && kind == MD_CODE_SYNTAX? r_print_code_tocolor (text, NULL): NULL;
	const char *p = colored? colored: text;
	const char *foreground = Color_WHITE;
	while (*p) {
		const char *background = "\x1b[48;5;234m";
		if (highlight && kind == MD_CODE_DIFF) {
			background = *p == '+'? "\x1b[48;5;22m": *p == '-'? "\x1b[48;5;52m": background;
			foreground = r_str_startswith (p, "@@")? Color_CYAN: Color_WHITE;
		}
		if (!fenced && *p == '\n') {
			r_strbuf_append (out, "\n");
			p++;
		} else {
			p = md_render_code_line (p, out, content_width, indent, padding, usecolor, colored != NULL, background, &foreground);
		}
	}
	free (colored);
	r_strbuf_set (code, "");
}

static bool md_render_hr(const char *line, RStrBuf *sb, const RMarkdownOptions *options, int maxcol) {
	line = r_str_trim_head_ro (line);
	size_t dashes = strspn (line, "-");
	if (dashes < 3 || *r_str_trim_head_ro (line + dashes)) {
		return false;
	}
	const int width = maxcol / 2;
	char *rule = r_str_repeat (options->utf8? RUNE_LONG_LINE_HORIZ: "-", width);
	if (rule) {
		r_strbuf_appendf (sb, "%*s%s\n", (maxcol - width) / 2, "", rule);
		free (rule);
	}
	return true;
}

static bool md_table_is_sep(const char *line, size_t len) {
	bool has_dash = false;
	size_t i;
	for (i = 0; i < len; i++) {
		char c = line[i];
		if (c == '-') {
			has_dash = true;
		} else if (c != '|' && c != ':' && c != ' ' && c != '\t') {
			return false;
		}
	}
	return has_dash;
}

static RList *md_table_split_row(const char *line, size_t len) {
	RList *cells = r_list_newf (free);
	char *row = r_str_trim_ndup (line, len);
	if (!row) {
		return cells;
	}
	char *p = row;
	const bool had_leading_pipe = *p == '|';
	if (had_leading_pipe) {
		p++;
	}
	for (;;) {
		char *start = p;
		while (*p && *p != '|') {
			if (*p == '\\' && p[1] == '|') {
				p++;
			}
			p++;
		}
		bool have_sep = *p;
		if (have_sep) {
			*p++ = 0;
		}
		r_str_trim (start);
		r_list_append (cells, strdup (start));
		if (!have_sep) {
			break;
		}
	}
	if (had_leading_pipe && !r_list_empty (cells)) {
		char *last = r_list_last (cells);
		if (R_STR_ISEMPTY (last)) {
			free (r_list_pop (cells));
		}
	}
	free (row);
	return cells;
}

static char *md_render_inline(const char *b, const RMarkdownOptions *options);

static void md_table_render(RTable *table, RStrBuf *out, int width, bool color) {
	int columns = r_list_length (table->cols);
	int limit = (width - 1) / columns - 3;
	RListIter *iter, *cell_iter;
	RTableColumn *col;
	RTableRow *row;
	if (limit < 2) {
		r_list_foreach (table->rows, iter, row) {
			RListIter *column_iter = table->cols->head;
			const char *cell;
			r_list_foreach (row->items, cell_iter, cell) {
				col = column_iter->data;
				char *field = r_str_newf ("%s: %s", col->name, cell);
				if (field) {
					md_append_wrapped (out, field, width, "", "", color, true);
					free (field);
				}
				column_iter = column_iter->n;
			}
			if (iter->n) {
				r_strbuf_append (out, "\n");
			}
		}
		if (r_list_empty (table->rows)) {
			r_list_foreach (table->cols, iter, col) {
				md_append_wrapped (out, col->name, width, "", "", color, true);
			}
		}
		return;
	}
	r_list_foreach (table->cols, iter, col) {
		col->maxWidth = R_MIN ((size_t)width, r_str_len_utf8_ansi (col->name) + 1);
	}
	r_list_foreach (table->rows, iter, row) {
		RListIter *column_iter = table->cols->head;
		const char *cell;
		r_list_foreach (row->items, cell_iter, cell) {
			col = column_iter->data;
			int cell_width = R_MIN ((size_t)width, r_str_len_utf8_ansi (cell) + 1);
			col->maxWidth = R_MAX (col->maxWidth, cell_width);
			column_iter = column_iter->n;
		}
	}
	const int budget = width - 1 - 3 * columns;
	int high = budget;
	while (limit < high) {
		int middle = limit + (high - limit + 1) / 2;
		ut64 used = 0;
		r_list_foreach (table->cols, iter, col) {
			used += R_MIN (middle, col->maxWidth);
		}
		if (used <= budget) {
			limit = middle;
		} else {
			high = middle - 1;
		}
	}
	int remaining = budget;
	r_list_foreach (table->cols, iter, col) {
		col->width = R_MIN (limit, col->maxWidth);
		remaining -= col->width;
	}
	r_list_foreach (table->cols, iter, col) {
		if (remaining && col->width < col->maxWidth) {
			col->width++;
			remaining--;
		}
		char *wrapped = md_wrap_text (col->name, col->width);
		if (wrapped) {
			free (col->name);
			col->name = wrapped;
		}
	}
	r_list_foreach (table->rows, iter, row) {
		RListIter *column_iter = table->cols->head;
		char *cell;
		r_list_foreach (row->items, cell_iter, cell) {
			col = column_iter->data;
			char *wrapped = md_wrap_text (cell, col->width);
			if (wrapped) {
				free (cell);
				cell_iter->data = wrapped;
			}
			column_iter = column_iter->n;
		}
	}
	table->widthsDirty = false;
	char *rendered = r_table_tofancystring (table);
	if (rendered) {
		r_strbuf_append (out, rendered);
		free (rendered);
	}
}

static int md_render_table(const char *b, RStrBuf *out, const RMarkdownOptions *options, int width) {
	const char *header_end = strchr (b, '\n');
	if (!header_end) {
		return 0;
	}
	size_t header_len = header_end - b;
	if (!memchr (b, '|', header_len)) {
		return 0;
	}
	const char *sep_start = header_end + 1;
	const char *sep_end = strchr (sep_start, '\n');
	size_t sep_len = sep_end? (size_t)(sep_end - sep_start): strlen (sep_start);
	if (!md_table_is_sep (sep_start, sep_len)) {
		return 0;
	}

	RList *headers = md_table_split_row (b, header_len);
	if (r_list_empty (headers)) {
		r_list_free (headers);
		return 0;
	}
	RList *seps = md_table_split_row (sep_start, sep_len);

	RTableOptions table_options = {
		.utf8 = options->utf8,
		.utf8_curvy = options->utf8_curvy,
		.wrap = true,
	};
	RTable *t = r_table_new ("md", &table_options);
	RListIter *iter;
	const char *h;
	int idx = 0;
	r_list_foreach (headers, iter, h) {
		char *rh = md_render_inline (h, options);
		r_table_add_column (t, r_table_type ("string"), rh? rh: h, 0);
		free (rh);
		const char *sep_cell = r_list_get_n (seps, idx);
		if (sep_cell && r_str_endswith (sep_cell, ":")) {
			r_table_align (t, idx, *sep_cell == ':'? R_TABLE_ALIGN_CENTER: R_TABLE_ALIGN_RIGHT);
		}
		idx++;
	}
	r_list_free (headers);
	r_list_free (seps);

	int ncols = r_list_length (t->cols);
	const char *p = sep_end? sep_end + 1: sep_start + sep_len;
	while (*p) {
		const char *eol = strchr (p, '\n');
		size_t len = eol? (size_t)(eol - p): strlen (p);
		if (!memchr (p, '|', len)) {
			break;
		}
		RList *cells = md_table_split_row (p, len);
		int nc = r_list_length (cells);
		while (nc < ncols) {
			r_list_append (cells, strdup (""));
			nc++;
		}
		while (nc > ncols) {
			free (r_list_pop (cells));
			nc--;
		}
		char *cell;
		RListIter *citer;
		r_list_foreach (cells, citer, cell) {
			char *rendered = md_render_inline (cell, options);
			if (rendered) {
				free (cell);
				citer->data = rendered;
			}
		}
		r_table_add_row_list (t, cells);
		p += len + (eol != NULL);
	}

	md_table_render (t, out, width, options->color);
	r_table_free (t);
	return p - b;
}

static bool md_escaped(const char *b) {
	return b[0] == '\\' && b[1] && strchr ("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", b[1]);
}

static int md_marker_run(const char *b, const char *end) {
	const char *p = b;
	while (p < end && *p == *b) {
		p++;
	}
	return p - b;
}

static const char *md_closing_marker(const char *b, const char *end, int count) {
	const char marker = *b;
	const char *p = b + count;
	while (p < end) {
		if (marker != '`' && md_escaped (p)) {
			p += 2;
			continue;
		}
		if (*p == marker) {
			int run = md_marker_run (p, end);
			if (marker == '`') {
				if (run == count) {
					return p;
				}
			} else if (run >= count && (count != 1 || run != 2)
				&& !isspace ((ut8)p[-1])
				&& (marker != '_' || p + run == end || !isalnum ((ut8)p[run]))) {
				return p + run - count;
			}
			p += run;
		} else if (marker != '`' && *p == '`') {
			int ticks = md_marker_run (p, end);
			const char *close = md_closing_marker (p, end, ticks);
			p = close? close + ticks: p + ticks;
		} else {
			p++;
		}
	}
	return NULL;
}

static void md_inline(RStrBuf *sb, const char *text, const char *end, bool color, int style, int depth);

static const char *md_link(RStrBuf *sb, const char *b, const char *end, bool color, int style, int depth) {
	const char *label = b + 1;
	const char *p = label;
	int brackets = 1;
	while (p < end && brackets) {
		if (md_escaped (p)) {
			p += 2;
			continue;
		}
		if (*p == '[') {
			brackets++;
		} else if (*p == ']') {
			brackets--;
		}
		if (brackets) {
			p++;
		}
	}
	if (p + 1 >= end || p[1] != '(') {
		return NULL;
	}
	const char *label_end = p;
	const char *url = p + 2;
	while (url < end && isspace ((ut8)*url)) {
		url++;
	}
	p = url;
	int parentheses = 0;
	bool angled = p < end && *p == '<';
	if (angled) {
		p++;
		url = p;
	}
	while (p < end) {
		if (md_escaped (p)) {
			p += 2;
			continue;
		}
		if (angled) {
			if (*p == '>') {
				break;
			}
		} else if (*p == '(') {
			parentheses++;
		} else if (*p == ')') {
			if (!parentheses) {
				break;
			}
			parentheses--;
		} else if (isspace ((ut8)*p)) {
			break;
		}
		p++;
	}
	const char *url_end = p;
	if (angled) {
		if (p == end || *p++ != '>') {
			return NULL;
		}
	}
	while (p < end && isspace ((ut8)*p)) {
		p++;
	}
	if (p < end && (*p == '"' || *p == '\'')) {
		char quote = *p++;
		while (p < end && *p != quote) {
			p += md_escaped (p)? 2: 1;
		}
		if (p == end) {
			return NULL;
		}
		p++;
		while (p < end && isspace ((ut8)*p)) {
			p++;
		}
	}
	if (p == end || *p != ')' || parentheses) {
		return NULL;
	}
	md_inline (sb, label, label_end, color, style, depth + 1);
	if (url_end > url && (label_end - label != url_end - url || memcmp (label, url, url_end - url))) {
		r_strbuf_append (sb, " (");
		while (url < url_end) {
			if (md_escaped (url)) {
				url++;
			}
			r_strbuf_append_n (sb, url++, 1);
		}
		r_strbuf_append (sb, ")");
	}
	return p + 1;
}

static void md_inline(RStrBuf *sb, const char *text, const char *end, bool color, int style, int depth) {
	const char *b = text;
	while (b < end) {
		if (md_escaped (b)) {
			r_strbuf_append_n (sb, b + 1, 1);
			b += 2;
			continue;
		}
		if (*b == '[' && depth < 32) {
			const char *next = md_link (sb, b, end, color, style, depth);
			if (next) {
				b = next;
				continue;
			}
		}
		if (strchr ("`*_~", *b) && depth < 32) {
			int run = md_marker_run (b, end);
			int count = *b == '`'? run: R_MIN (run, *b == '~'? 2: 3);
			bool emphasis = *b != '`';
			bool valid = !emphasis || (b + count < end && !isspace ((ut8)b[count])
				&& (*b != '_' || b == text || !isalnum ((ut8)b[-1]))
				&& (*b != '~' || count == 2));
			const char *close = valid? md_closing_marker (b, end, count): NULL;
			if (close) {
				int attr = *b == '`'? MD_CODE: *b == '~'? MD_STRIKE:
					count == 3? MD_BOLD | MD_ITALIC: count == 2? MD_BOLD: MD_ITALIC;
				if (color) {
					md_style (sb, attr);
				}
				if (emphasis) {
					md_inline (sb, b + count, close, color, style | attr, depth + 1);
				} else {
					r_strbuf_append_n (sb, b + count, close - b - count);
				}
				if (color) {
					if (attr == MD_CODE) {
						r_strbuf_append (sb, Color_RESET_BG Color_RESET);
						md_style (sb, style);
					} else {
						if ((attr & MD_BOLD) && !(style & MD_BOLD)) {
							r_strbuf_append (sb, Color_BOLD_RESET);
						}
						if ((attr & MD_ITALIC) && !(style & MD_ITALIC)) {
							r_strbuf_append (sb, Color_ITALIC_RESET);
						}
						if ((attr & MD_STRIKE) && !(style & MD_STRIKE)) {
							r_strbuf_append (sb, Color_STRIKE_RESET);
						}
					}
				}
				b = close + count;
				continue;
			}
		}
		if (*b == '\t') {
			r_strbuf_append (sb, "  ");
		} else if (*b != '\r') {
			r_strbuf_append_n (sb, b, 1);
		}
		b++;
	}
}

static char *md_render_inline(const char *b, const RMarkdownOptions *options) {
	RStrBuf *sb = r_strbuf_new ("");
	md_inline (sb, b, b + strlen (b), options->color, 0, 0);
	return r_strbuf_drain (sb);
}

static void md_render_slide_title(RStrBuf *sb, const char *title, size_t title_len, int level, int maxcol, bool usecolor) {
	char *title_str = r_str_ndup (title, (int)title_len);
	if (!title_str) {
		return;
	}
	if (level == 1) {
		char *big = r_str_ss (title_str, NULL, 0);
		if (!big) {
			free (title_str);
			return;
		}
		char *p = big;
		char *nextline;
		if (usecolor) {
			r_strbuf_append (sb, Color_BLACK Color_BGGREEN);
		}
		while ((nextline = strchr (p, '\n'))) {
			int len = nextline - p;
			r_strbuf_append_n (sb, p, len);
			r_strbuf_appendf (sb, "%*s", R_MAX (0, maxcol + 1 - len), "");
			r_strbuf_append (sb, usecolor? "   " Color_RESET_BG Color_RESET "\n" Color_BGGREEN Color_BLACK: "   \n");
			p = nextline + 1;
		}
		free (big);
		r_strbuf_append (sb, usecolor? Color_RESET_BG Color_RESET "\n": "\n");
		free (title_str);
		return;
	}

	if (usecolor) {
		r_strbuf_append (sb, Color_BLACK Color_BGBLUE);
		fill_line (sb, maxcol + 4);
		r_strbuf_append (sb, level > 2? Color_BLUE Color_BGCYAN: Color_BLACK Color_BGBLUE);
	}
	r_strbuf_appendf (sb, "  %s", title_str);
	if (usecolor) {
		fill_line (sb, maxcol + 2 - (int)r_str_len_utf8 (title_str));
		r_strbuf_append (sb, Color_BLACK Color_BGBLUE);
		fill_line (sb, maxcol + 4);
	} else {
		r_strbuf_append (sb, "\n");
	}
	free (title_str);
}

static bool md_render_title(const char *b, RStrBuf *sb, const RMarkdownOptions *options, int maxcol) {
	int level = 0;
	while (level < 6 && b[level] == '#') {
		level++;
	}
	if (!level || (b[level] && !strchr (" \t\n\r", b[level]))) {
		return false;
	}
	const char *title = b + level + strspn (b + level, " \t");
	const char *end = title + strcspn (title, "\n\r");
	const char *trimmed_end = end;
	while (trimmed_end > title && (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t')) {
		trimmed_end--;
	}
	const size_t title_len = trimmed_end - title;
	const bool usecolor = options->color;
	bool slide_rendered = false;
	if (options->slide_titles && maxcol > 4) {
		RStrBuf *slide = r_strbuf_new ("");
		md_render_slide_title (slide, title, title_len, level, maxcol - 4, usecolor);
		slide_rendered = !r_strbuf_is_empty (slide) && r_str_bounds (r_strbuf_get (slide), NULL) <= maxcol;
		if (slide_rendered) {
			r_strbuf_append (sb, r_strbuf_get (slide));
		}
		r_strbuf_free (slide);
	}
	if (!slide_rendered) {
		RStrBuf *title_buf = r_strbuf_new ("");
		if (usecolor) {
			r_strbuf_append (title_buf, Color_BBLUE);
		}
		r_strbuf_append_n (title_buf, b, level);
		if (usecolor) {
			r_strbuf_append (title_buf, Color_RESET);
		}
		if (title_len) {
			r_strbuf_append (title_buf, " ");
			if (usecolor) {
				r_strbuf_append (title_buf, Color_BOLD);
			}
			md_inline (title_buf, title, trimmed_end, usecolor, MD_BOLD, 0);
			if (usecolor) {
				r_strbuf_append (title_buf, Color_RESET);
			}
		}
		md_append_wrapped (sb, r_strbuf_get (title_buf), maxcol, "", "", usecolor, true);
		r_strbuf_free (title_buf);
	}
	return true;
}

static int md_fence(const char *line, int *indent) {
	const char *p = line;
	while (*p == ' ' && p - line < 3) {
		p++;
	}
	*indent = p - line;
	if (*p != '`' && *p != '~') {
		return 0;
	}
	const char *start = p;
	while (*p == *start) {
		p++;
	}
	return p - start >= 3? p - start: 0;
}

static int md_list_marker(const char *line) {
	const char *p = line;
	if (*p == '-' || *p == '*' || *p == '+') {
		p++;
	} else {
		while (isdigit ((ut8)*p) && p - line < 9) {
			p++;
		}
		if (p == line || (*p != '.' && *p != ')')) {
			return 0;
		}
		p++;
	}
	if (*p != ' ' && *p != '\t') {
		return 0;
	}
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	return p - line;
}

R_API char *r_str_md2txt_ex(const char *md, const RMarkdownOptions *options, int width, bool highlight) {
	R_RETURN_VAL_IF_FAIL (md, NULL);
	RMarkdownOptions default_options = {0};
	if (!options) {
		options = &default_options;
	}
	width = width > 0? width: 75;
	RStrBuf *out = r_strbuf_new ("");
	RStrBuf *code = r_strbuf_new ("");
	MDCodeKind code_kind = MD_CODE_SYNTAX;
	char fence_marker = 0;
	int fence_length = 0;
	int fence_indent = 0;
	int list_indent = 0;
	int list_quotes = 0;
	const char *b = md;
	while (*b) {
		const char *eol = strchr (b, '\n');
		const char *next = eol? eol + 1: b + strlen (b);
		char *line = r_str_ndup (b, (eol? eol: next) - b);
		if (!line) {
			break;
		}
		size_t length = strlen (line);
		if (length && line[length - 1] == '\r') {
			line[--length] = 0;
		}
		int indent;
		int run = md_fence (line, &indent);
		if (fence_length) {
			if (run >= fence_length && line[indent] == fence_marker
				&& !*r_str_trim_head_ro (line + indent + run)) {
				md_render_code (code, out, width, options->color, highlight, code_kind, true);
				fence_length = 0;
			} else {
				int skip = 0;
				while (skip < fence_indent && line[skip] == ' ') {
					skip++;
				}
				r_strbuf_append (code, line + skip);
				r_strbuf_append (code, "\n");
			}
		} else if (run && (line[indent] != '`' || !strchr (line + indent + run, '`'))) {
			md_render_code (code, out, width, options->color, highlight, MD_CODE_SYNTAX, false);
			code_kind = md_code_kind (line + indent + run);
			fence_marker = line[indent];
			fence_length = run;
			fence_indent = indent;
			list_indent = 0;
		} else if (!*r_str_trim_head_ro (line)) {
			r_strbuf_append (r_strbuf_is_empty (code)? out: code, "\n");
		} else {
			const char *content = line;
			while (*content == ' ') {
				content++;
			}
			indent = content - line;
			int quotes = 0;
			while (*content == '>') {
				quotes++;
				content++;
				if (*content == ' ') {
					content++;
				}
			}
			if (quotes) {
				indent = 0;
				while (*content == ' ') {
					indent++;
					content++;
				}
			}
			int marker = md_list_marker (content);
			bool continuation = list_indent && quotes == list_quotes && indent >= list_indent;
			bool indented_code = !quotes && !marker && (*line == '\t' || indent >= (continuation? list_indent + 4: 4));
			if (!indented_code) {
				md_render_code (code, out, width, options->color, highlight, MD_CODE_SYNTAX, false);
			}
			if (indented_code) {
				int skip = *line == '\t'? 1: (continuation? list_indent: 0) + 4;
				r_strbuf_append (code, line + skip);
				r_strbuf_append (code, "\n");
			} else if (!quotes && !marker && md_render_title (content, out, options, width)) {
				list_indent = 0;
			} else if (!quotes && md_render_hr (content, out, options, width)) {
				list_indent = 0;
			} else {
				int table_length = !quotes && !marker? md_render_table (b, out, options, width): 0;
				if (table_length) {
					next = b + table_length;
					list_indent = 0;
				} else {
					RStrBuf *prefix = r_strbuf_new (width > 3? "  ": "");
					int i;
					for (i = 0; i < quotes; i++) {
						r_strbuf_append (prefix, "> ");
					}
					r_strbuf_appendf (prefix, "%*s", indent, "");
					RStrBuf *rest = r_strbuf_new (r_strbuf_get (prefix));
					if (marker) {
						int marker_width = marker;
						int source_marker = marker;
						const char *task = content + marker;
						bool checkbox = !isdigit ((ut8)*content) && task[0] == '['
							&& (task[1] == ' ' || task[1] == 'x' || task[1] == 'X')
							&& task[2] == ']' && (!task[3] || isspace ((ut8)task[3]));
						if (checkbox) {
							bool checked = task[1] != ' ';
							const char *box = options->utf8? checked? "􁁛": "􀟈": checked? "[x]": "[ ]";
							if (options->color) {
								r_strbuf_append (prefix, Color_BBLUE);
							}
							int spacing = options->utf8? 2: 1;
							r_strbuf_appendf (prefix, "%s%*s", box, spacing, "");
							if (options->color) {
								r_strbuf_append (prefix, Color_RESET);
							}
							marker_width = r_str_len_utf8 (box) + spacing;
							marker += 3;
							while (content[marker] == ' ' || content[marker] == '\t') {
								marker++;
							}
						} else {
							for (i = 0; i < marker; i++) {
								if (!i && !isdigit ((ut8)*content)) {
									if (options->color) {
										r_strbuf_append (prefix, Color_BBLUE);
									}
									if (options->utf8) {
										r_strbuf_append (prefix, "•");
									} else {
										r_strbuf_append_n (prefix, content, 1);
									}
									if (options->color) {
										r_strbuf_append (prefix, Color_RESET);
									}
								} else if (content[i] == '\t') {
									r_strbuf_append (prefix, "  ");
									marker_width++;
								} else {
									r_strbuf_append_n (prefix, content + i, 1);
								}
							}
						}
						r_strbuf_appendf (rest, "%*s", marker_width, "");
						list_indent = indent + source_marker;
						list_quotes = quotes;
						content += marker;
					} else if (!continuation) {
						list_indent = 0;
					}
					char *rendered = md_render_inline (content, options);
					if (rendered) {
						md_append_wrapped (out, rendered, width, r_strbuf_get (prefix), r_strbuf_get (rest), options->color, eol != NULL);
						free (rendered);
					}
					r_strbuf_free (prefix);
					r_strbuf_free (rest);
				}
			}
		}
		free (line);
		b = next;
	}
	md_render_code (code, out, width, options->color, highlight, fence_length? code_kind: MD_CODE_SYNTAX, fence_length != 0);
	r_strbuf_free (code);
	return r_strbuf_drain (out);
}

R_API char *r_str_md2txt_width(const char *md, const RMarkdownOptions *options, int width) {
	return r_str_md2txt_ex (md, options, width, false);
}

R_API char *r_str_md2txt(const char *md, const RMarkdownOptions *options) {
	return r_str_md2txt_width (md, options, 75);
}
