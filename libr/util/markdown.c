/* radare - LGPL - Copyright 2007-2026 - pancake */

#include <r_bin.h>
#include <r_util/r_table.h>

static void fill_line(RStrBuf *sb, int maxcol) {
	if (maxcol < 1) {
		return;
	}
	r_strbuf_appendf (sb, "%*s", maxcol, "");
	r_strbuf_append (sb, Color_RESET_BG);
	r_strbuf_append (sb, Color_RESET);
	r_strbuf_append (sb, "\n");
}

static void cb_start(RStrBuf *sb, bool usecolor) {
	if (usecolor) {
		r_strbuf_append (sb, "  \x1b[48;5;234m " Color_WHITE);
	} else {
		r_strbuf_append (sb, "   ");
	}
}

static int md_render_hr(const char *b, RStrBuf *sb, const RMarkdownOptions *options, int maxcol) {
	const char *eol = strchr (b, '\n');
	const size_t len = eol? (size_t)(eol - b): strlen (b);
	char *text = r_str_trim_ndup (b, len);
	if (!text) {
		return 0;
	}
	const char *p = text;
	while (*p == '-') {
		p++;
	}
	if (p - text < 3 || *p) {
		free (text);
		return 0;
	}
	free (text);
	const int width = maxcol / 2;
	char *line = r_str_repeat (options && options->utf8? RUNE_LONG_LINE_HORIZ: "-", width);
	if (line) {
		r_strbuf_appendf (sb, "%*s%s\n", (maxcol - width) / 2, "", line);
		free (line);
	}
	return (int)(eol? eol + 1 - b: len);
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
		if (!*p) {
			r_list_append (cells, strdup (""));
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

static int md_table_col_align(const char *cell, size_t len) {
	char *s = r_str_trim_ndup (cell, len);
	if (!s) {
		return R_TABLE_ALIGN_LEFT;
	}
	size_t slen = strlen (s);
	bool left = *s == ':';
	bool right = slen > 0 && s[slen - 1] == ':';
	free (s);
	if (left && right) {
		return R_TABLE_ALIGN_CENTER;
	}
	if (right) {
		return R_TABLE_ALIGN_RIGHT;
	}
	return R_TABLE_ALIGN_LEFT;
}

static char *md_render_inline(const char *b, const RMarkdownOptions *options);

static int md_render_table(const char *b, RStrBuf *out, const RMarkdownOptions *options) {
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
		.utf8 = options && options->utf8,
		.utf8_curvy = options && options->utf8_curvy,
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
		if (sep_cell) {
			r_table_align (t, idx, md_table_col_align (sep_cell, strlen (sep_cell)));
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
		size_t i;
		bool has_pipe = false;
		bool only_ws = true;
		for (i = 0; i < len; i++) {
			if (p[i] == '|') {
				has_pipe = true;
			}
			if (p[i] != ' ' && p[i] != '\t') {
				only_ws = false;
			}
		}
		if (only_ws || !has_pipe) {
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
		if (!eol) {
			p += len;
			break;
		}
		p = eol + 1;
	}

	char *rendered = r_table_tofancystring (t);
	r_table_free (t);
	if (R_STR_ISNOTEMPTY (rendered)) {
		r_strbuf_append (out, rendered);
	}
	free (rendered);
	return p - b;
}

static int md_emphasis(const char *b, RStrBuf *sb, bool *bold, bool *italic, bool *strike) {
	char m = *b;
	if (m != '*' && m != '_') {
		return 0;
	}
	const bool dbl = (b[1] == m);
	if (dbl) {
		if (*bold) {
			r_strbuf_append (sb, Color_BOLD_RESET);
			*bold = false;
			return 2;
		}
		const char *p = b + 2;
		while (*p && *p != '\n') {
			if (p[0] == m && p[1] == m) {
				r_strbuf_append (sb, Color_BOLD);
				*bold = true;
				return 2;
			}
			p++;
		}
		return 0;
	}
	if (*italic) {
		r_strbuf_append (sb, Color_ITALIC_RESET);
		*italic = false;
		return 1;
	}
	const char *p = b + 1;
	while (*p && *p != '\n') {
		if (p[0] == m && p[1] == m) {
			p += 2;
			continue;
		}
		if (p[0] == m) {
			r_strbuf_append (sb, Color_ITALIC);
			*italic = true;
			return 1;
		}
		p++;
	}
	return 0;
}

static int md_strikethrough(const char *b, RStrBuf *sb, bool *strike) {
	if (b[0] != '~' || b[1] != '~') {
		return 0;
	}
	if (*strike) {
		r_strbuf_append (sb, Color_STRIKE_RESET);
		*strike = false;
		return 2;
	}
	const char *p = b + 2;
	while (*p && *p != '\n') {
		if (p[0] == '~' && p[1] == '~') {
			r_strbuf_append (sb, Color_STRIKE);
			*strike = true;
			return 2;
		}
		p++;
	}
	return 0;
}

static char *md_render_inline(const char *b, const RMarkdownOptions *options) {
	R_RETURN_VAL_IF_FAIL (b, NULL);
	if (!options || !options->utf8) {
		return strdup (b);
	}
	RStrBuf *sb = r_strbuf_new ("");
	bool bold = false;
	bool italic = false;
	bool strike = false;
	while (*b) {
		int ch = *b;
		if (ch == '*' || ch == '_') {
			int n = md_emphasis (b, sb, &bold, &italic, &strike);
			if (n > 0) {
				b += n;
				continue;
			}
		}
		if (ch == '~') {
			int n = md_strikethrough (b, sb, &strike);
			if (n > 0) {
				b += n;
				continue;
			}
		}
		r_strbuf_appendf (sb, "%c", ch);
		b++;
	}
	return r_strbuf_drain (sb);
}

static int md_title_level(const char *b) {
	int level = 0;
	while (level < 6 && b[level] == '#') {
		level++;
	}
	if (level < 1) {
		return 0;
	}
	const char next = b[level];
	return (next == ' ' || next == '\t' || next == '\n' || next == '\r' || !next)
		? level: 0;
}

static void md_render_slide_title(RStrBuf *sb, const char *title, size_t title_len, int level, int maxcol, bool usecolor) {
	char *title_str = r_str_ndup (title, (int)title_len);
	if (level == 1) {
		char *big = r_str_ss (title_str, NULL, 0);
		char *p = big;
		char *nextline = strstr (p, "\n");
		if (usecolor) {
			r_strbuf_append (sb, Color_BLACK);
			r_strbuf_append (sb, Color_BGGREEN);
		}
		while (nextline) {
			char *line = r_str_ndup (p, nextline - p);
			r_strbuf_append (sb, line);
			int col = strlen (line);
			int i;
			for (i = col; i < maxcol + 1; i++) {
				r_strbuf_append (sb, " ");
			}
			if (usecolor) {
				r_strbuf_append (sb, "  ");
				r_strbuf_append (sb, " " Color_RESET_BG "" Color_RESET "\n" Color_BGGREEN "" Color_BLACK);
			} else {
				r_strbuf_append (sb, "   \n");
			}
			free (line);
			p = nextline + 1;
			nextline = strstr (p, "\n");
		}
		free (big);
		if (usecolor) {
			r_strbuf_append (sb, Color_RESET_BG "" Color_RESET "\n");
		} else {
			r_strbuf_append (sb, "\n");
		}
		free (title_str);
		return;
	}

	if (usecolor) {
		r_strbuf_append (sb, Color_BLACK);
		r_strbuf_append (sb, Color_BGBLUE);
		fill_line (sb, maxcol + 4);
		if (level > 2) {
			r_strbuf_append (sb, Color_BLUE);
			r_strbuf_append (sb, Color_BGCYAN);
		} else {
			r_strbuf_append (sb, Color_BLACK);
			r_strbuf_append (sb, Color_BGBLUE);
		}
	}
	r_strbuf_appendf (sb, "  %s", title_str);
	if (usecolor) {
		fill_line (sb, maxcol + 2 - 2 - (int)title_len);
		r_strbuf_append (sb, Color_BLACK);
		r_strbuf_append (sb, Color_BGBLUE);
		fill_line (sb, maxcol + 4);
	} else {
		r_strbuf_append (sb, "\n");
	}
	free (title_str);
}

static int md_render_title(const char *b, RStrBuf *sb, const RMarkdownOptions *options, int maxcol) {
	const int level = md_title_level (b);
	if (level < 1) {
		return 0;
	}
	const char *title = b + level;
	while (*title == ' ' || *title == '\t') {
		title++;
	}
	const char *end = title;
	while (*end && *end != '\n' && *end != '\r') {
		end++;
	}
	const char *trimmed_end = end;
	while (trimmed_end > title && (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t')) {
		trimmed_end--;
	}
	const size_t title_len = trimmed_end - title;
	const bool usecolor = options && options->color;
	if (options && options->slide_titles) {
		md_render_slide_title (sb, title, title_len, level, maxcol, usecolor);
	} else {
		int i;
		if (usecolor) {
			r_strbuf_append (sb, Color_BBLUE);
		}
		for (i = 0; i < level; i++) {
			r_strbuf_append (sb, "#");
		}
		if (usecolor) {
			r_strbuf_append (sb, Color_RESET);
		}
		if (title_len > 0) {
			r_strbuf_append (sb, " ");
			if (usecolor) {
				r_strbuf_append (sb, Color_BOLD);
			}
			r_strbuf_append_n (sb, title, title_len);
			if (usecolor) {
				r_strbuf_append (sb, Color_RESET);
			}
		}
		r_strbuf_append (sb, "\n");
	}
	while (*end == '\r' || *end == '\n') {
		end++;
		if (end[-1] == '\n') {
			break;
		}
	}
	return end - b;
}

R_API char *r_str_md2txt(const char *md, const RMarkdownOptions *options) {
	R_RETURN_VAL_IF_FAIL (md, NULL);
	RMarkdownOptions default_options = {0};
	if (!options) {
		options = &default_options;
	}
	const bool usecolor = options->color;
	const bool useutf8 = options->utf8;
	const char *b = md;
	RStrBuf *sb = r_strbuf_new ("");
	int col = 0;
	const int maxcol = 75;
	bool codeblock = false;
	bool codeblockline = false;
	bool bold = false;
	bool italic = false;
	bool strike = false;
	while (*b) {
		int ch = *b;
	repeat:
		switch (ch) {
		case 10: // '\n'
			if (codeblock) {
				const int j = maxcol - 4;
				if (usecolor) {
					if (col == 0) {
						cb_start (sb, true);
					}
					fill_line (sb, j - col);
				} else {
					r_strbuf_append (sb, "\n");
				}
			} else if (usecolor) {
				r_strbuf_append (sb, Color_RESET);
				r_strbuf_append (sb, "\n");
			} else {
				r_strbuf_append (sb, "\n");
			}
			col = 0;
			if (codeblockline) {
				codeblock = false;
				codeblockline = false;
			}
			bold = false;
			italic = false;
			strike = false;
			break;
		case '\t':
			if (col == 0) {
				codeblock = true;
				codeblockline = true;
			} else {
				r_strbuf_append (sb, "  ");
			}
			break;
		case 13:
			// ignore
			break;
		default:
			if (col > maxcol) {
				ch = 10;
				if (*b == ' ') {
					b++;
				} else {
					if (codeblock) {
						col = 1;
						// nothing
					} else {
						r_strbuf_append (sb, "-");
					}
				}
				b--;
				goto repeat;
			}
			if (col == 0) {
				if (r_str_startswith (b, "```")) {
					while (*b && *b != '\n') {
						b++;
					}
					codeblock = !codeblock;
					if (usecolor && !codeblock) {
						r_strbuf_append (sb, Color_RESET_BG);
					}
					if (*b == '\n') {
						b++;
					}
					continue;
				}
				if (!codeblock) {
					int tlen = md_render_title (b, sb, options, maxcol);
					if (tlen > 0) {
						b += tlen;
						col = 0;
						continue;
					}
					tlen = md_render_hr (b, sb, options, maxcol);
					if (tlen > 0) {
						b += tlen;
						continue;
					}
					tlen = md_render_table (b, sb, options);
					if (tlen > 0) {
						b += tlen;
						continue;
					}
				}
				if (codeblock) {
					cb_start (sb, usecolor);
				} else {
					r_strbuf_append (sb, "  ");
				}
			}
			if (useutf8 && !codeblock && (ch == '*' || ch == '_')) {
				int n = md_emphasis (b, sb, &bold, &italic, &strike);
				if (n > 0) {
					b += n - 1;
					col++;
					break;
				}
			}
			if (useutf8 && !codeblock && ch == '~') {
				int n = md_strikethrough (b, sb, &strike);
				if (n > 0) {
					b += n - 1;
					col++;
					break;
				}
			}
			col++;
			r_strbuf_appendf (sb, "%c", ch);
			break;
		}
		b++;
	}
	return r_strbuf_drain (sb);
}
