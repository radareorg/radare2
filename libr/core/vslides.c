/* radare - LGPL - Copyright 2021-2026 - pancake */

#include <r_core.h>

typedef struct slides_state_t {
	char *keys[256];
} SlidesState;

typedef struct slides_match_t {
	int page;
	int x;
	int y;
	int ordinal;
} SlidesMatch;

typedef struct slides_search_t {
	char *word;
	RList *hits;
	int current;
	int width;
	bool focus;
} SlidesSearch;

typedef struct slides_view_t {
	SlidesState *state;
	RCore *core;
	RList *list;
	int mode;
	int page;
	int sx;
	int sy;
	int total_pages;
	SlidesSearch *search;
} SlidesView;

static void clearkeys(SlidesState *state) {
	int i;
	for (i = 0; i < 256; i++) {
		free (state->keys[i]);
	}
	memset (state, 0, sizeof (SlidesState));
}

static RList *slides_load(const char *data) {
	RList *list = r_str_split_duplist (data, "\n", false);
	RListIter *iter;
	char *line;
	r_list_foreach (list, iter, line) {
		r_str_trim_tail (line);
	}
	return list;
}

typedef struct slides_fence_t {
	char marker;
	size_t length;
} SlidesFence;

static bool slide_fence(SlidesFence *fence, const char *text) {
	if (*text != '`' && *text != '~') {
		return false;
	}
	size_t length = 0;
	while (text[length] == *text) {
		length++;
	}
	if (length < 3) {
		return false;
	}
	if (!fence->marker) {
		fence->marker = *text;
		fence->length = length;
		return true;
	}
	if (*text == fence->marker && length >= fence->length
			&& !*r_str_trim_head_ro (text + length)) {
		fence->marker = 0;
		fence->length = 0;
		return true;
	}
	return false;
}

static int findpage(RList *list, const char *pagename) {
	int count = 0;
	SlidesFence fence = {0};
	RListIter *iter;
	const char *s;
	r_list_foreach (list, iter, s) {
		s = r_str_trim_head_ro (s);
		if (slide_fence (&fence, s) || fence.marker) {
			continue;
		}
		if (r_str_startswith (s, "# ")) {
			count++;
		} else if (r_str_startswith (s, "--label:")) {
			const char *label = s + strlen ("--label:");
			if (!strcmp (pagename, label)) {
				return count;
			}
		}
	}
	return -1;
}

static int gotokey(SlidesState *state, RList *list, int ch, int page) {
	if (state->keys[ch]) {
		int npage = findpage (list, state->keys[ch]);
		if (npage != -1) {
			return npage;
		}
	}
	return page;
}

static int count_pages(RList *list) {
	int pages = 0;
	const char *s;
	SlidesFence fence = {0};
	RListIter *iter;
	r_list_foreach (list, iter, s) {
		s = r_str_trim_head_ro (s);
		if (slide_fence (&fence, s) || fence.marker) {
			continue;
		}
		if (r_str_startswith (s, "# ")) {
			pages++;
		}
	}
	return pages;
}

static int slide_line(RList *list, int page) {
	int line = 1;
	int current_page = 0;
	SlidesFence fence = {0};
	RListIter *iter;
	const char *text;
	r_list_foreach (list, iter, text) {
		text = r_str_trim_head_ro (text);
		if (slide_fence (&fence, text) || fence.marker) {
			line++;
			continue;
		}
		if (r_str_startswith (text, "# ") && ++current_page == page) {
			return line;
		}
		line++;
	}
	return 1;
}

static char *slide_block_title(const char *text, int width) {
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -~./:+?'&!=";
	static const char *glyphs[] = {
		"01110" "10001" "10001" "11111" "10001" "10001", // A
		"11110" "10001" "11110" "10001" "10001" "11110", // B
		"01111" "10000" "10000" "10000" "10000" "01111", // C
		"11110" "10001" "10001" "10001" "10001" "11110", // D
		"11111" "10000" "11110" "10000" "10000" "11111", // E
		"11111" "10000" "11110" "10000" "10000" "10000", // F
		"01111" "10000" "10011" "10001" "10001" "01111", // G
		"10001" "10001" "11111" "10001" "10001" "10001", // H
		"11111" "00100" "00100" "00100" "00100" "11111", // I
		"00111" "00010" "00010" "00010" "10010" "01100", // J
		"10001" "10010" "11100" "10100" "10010" "10001", // K
		"10000" "10000" "10000" "10000" "10000" "11111", // L
		"10001" "11011" "10101" "10101" "10001" "10001", // M
		"10001" "11001" "10101" "10011" "10001" "10001", // N
		"01110" "10001" "10001" "10001" "10001" "01110", // O
		"11110" "10001" "10001" "11110" "10000" "10000", // P
		"01110" "10001" "10001" "10101" "10010" "01101", // Q
		"11110" "10001" "10001" "11110" "10010" "10001", // R
		"01111" "10000" "01110" "00001" "00001" "11110", // S
		"11111" "00100" "00100" "00100" "00100" "00100", // T
		"10001" "10001" "10001" "10001" "10001" "01110", // U
		"10001" "10001" "10001" "10001" "01010" "00100", // V
		"10001" "10001" "10101" "10101" "10101" "01010", // W
		"10001" "01010" "00100" "00100" "01010" "10001", // X
		"10001" "10001" "01010" "00100" "00100" "00100", // Y
		"11111" "00001" "00010" "00100" "01000" "11111", // Z
		"01110" "10011" "10101" "10101" "11001" "01110", // 0
		"00100" "01100" "00100" "00100" "00100" "01110", // 1
		"01110" "10001" "00010" "00100" "01000" "11111", // 2
		"11110" "00001" "00110" "00001" "00001" "11110", // 3
		"00010" "00110" "01010" "10010" "11111" "00010", // 4
		"11111" "10000" "11110" "00001" "00001" "11110", // 5
		"01110" "10000" "11110" "10001" "10001" "01110", // 6
		"11111" "00001" "00010" "00100" "01000" "01000", // 7
		"01110" "10001" "01110" "10001" "10001" "01110", // 8
		"01110" "10001" "10001" "01111" "00001" "01110", // 9
		"00000" "00000" "00000" "00000" "00000" "00000", // space
		"00000" "00000" "11111" "00000" "00000" "00000", // -
		"00000" "01001" "10110" "00000" "00000" "00000", // ~
		"00000" "00000" "00000" "00000" "00110" "00110", // .
		"00001" "00010" "00100" "01000" "10000" "00000", // /
		"00000" "00110" "00110" "00000" "00110" "00110", // :
		"00000" "00100" "11111" "00100" "00000" "00000", // +
		"01110" "10001" "00010" "00100" "00000" "00100", // ?
		"00100" "00100" "00000" "00000" "00000" "00000", // '
		"01100" "10010" "01100" "10101" "10010" "01101", // &
		"00100" "00100" "00100" "00100" "00000" "00100", // !
		"00000" "11111" "00000" "11111" "00000" "00000", // =
	};
	int available = width - 4;
	const char *ch;
	for (ch = text; *ch; ch++) {
		int columns = *ch == ' '? 3: 6;
		if ((ut8)*ch >= 128 || !strchr (alphabet, toupper ((ut8)*ch)) || columns > available) {
			return NULL;
		}
		available -= columns;
	}
	RStrBuf *out = r_strbuf_new (NULL);
	int row, column;
	for (row = 0; row < 3; row++) {
		for (ch = text; *ch; ch++) {
			if (*ch == ' ') {
				r_strbuf_append (out, "   ");
				continue;
			}
			const char *glyph = glyphs[strchr (alphabet, toupper ((ut8)*ch)) - alphabet];
			for (column = 0; column < 5; column++) {
				bool top = glyph[row * 10 + column] == '1';
				bool bottom = glyph[row * 10 + column + 5] == '1';
				r_strbuf_append (out, top? bottom? "█": "▀": bottom? "▄": " ");
			}
			r_strbuf_append (out, " ");
		}
		r_strbuf_append (out, "\n");
	}
	return r_strbuf_drain (out);
}

static char *slide_background(RCore *core, const char *name) {
	if (!name || !strcmp (name, "theme")) {
		return strdup (core->cons->context->pal.widget_bg);
	}
	if (!*name || !strcmp (name, "none")) {
		return strdup (Color_RESET_BG);
	}
	RColor color = { .a = ALPHA_BG };
	if (*name == '@') {
		color = r_cons_pal_get (core->cons, name + 1);
		color.a = ALPHA_BG;
	} else {
		char *parsed = r_cons_pal_parse (core->cons, name, &color);
		if (!parsed) {
			return strdup (core->cons->context->pal.widget_bg);
		}
		free (parsed);
	}
	return r_cons_rgb_str (core->cons, NULL, 0, &color);
}

static void slide_heading(RCore *core, RStrBuf *out, const char *text, RListIter *settings, int width) {
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	bool color = r_config_get_i (core->config, "scr.color") > 0;
	bool primary = r_str_startswith (text, "# ");
	const char *font = primary? utf8? "block": "ascii": "sansserifbold";
	const char *background = "theme";
	RListIter *iter;
	for (iter = primary? settings: NULL; iter; iter = iter->n) {
		const char *setting = r_str_trim_head_ro (iter->data);
		if (!*setting) {
			continue;
		}
		if (!r_str_startswith (setting, "--")) {
			break;
		}
		if (r_str_startswith (setting, "--font=")) {
			font = setting + strlen ("--font=");
		} else if (r_str_startswith (setting, "--bgcolor=")) {
			background = setting + strlen ("--bgcolor=");
		}
	}
	while (*text == '#') {
		text++;
	}
	text = r_str_trim_head_ro (text);
	char *title = NULL;
	if (!strcmp (font, "block") && utf8) {
		title = slide_block_title (text, width);
	} else if (!strcmp (font, "ascii") || (!utf8 && !strcmp (font, "block"))) {
		title = r_str_ss (text, NULL, 0);
		if (title && r_str_bounds (title, NULL) > width - 4) {
			R_FREE (title);
		}
	}
	const char *family = NULL;
	if (!title) {
		if (utf8 && strcmp (font, "plain")) {
			family = !strcmp (font, "block") || !strcmp (font, "ascii")? "sansserifbold": font;
		}
		title = strdup (text);
	}
	if (!title) {
		return;
	}
	int margin = width > 4? 2: 0;
	char *wrapped = strchr (title, '\n')? title: r_str_wrap (title, R_MAX (1, width - 2 * margin));
	if (wrapped != title) {
		free (title);
	}
	if (!wrapped) {
		return;
	}
	char *bg = slide_background (core, background);
	char *row = wrapped;
	while (*row) {
		char *end = strchr (row, '\n');
		if (end) {
			*end = 0;
		}
		if (color) {
			r_strbuf_append (out, core->cons->context->pal.fname);
			r_strbuf_append (out, bg);
		}
		char *styled = family? r_font_render (row, family): NULL;
		const char *visible = styled? styled: row;
		r_strbuf_appendf (out, "%*s%s", margin, "", visible);
		if (color) {
			int padding = R_MAX (0, width - margin - (int)r_str_len_utf8_ansi (visible));
			r_strbuf_pad (out, ' ', padding);
			r_strbuf_append (out, Color_RESET);
		}
		r_strbuf_append (out, "\n");
		free (styled);
		if (!end) {
			break;
		}
		row = end + 1;
	}
	free (bg);
	free (wrapped);
}

static void slide_theme(RCore *core, RStrBuf *out, const char *text) {
	RConsPrintablePalette *pal = &core->cons->context->pal;
	RConsCodeColors code = r_cons_codecolors (core->cons);
	// Translate the Markdown renderer's default styles to the active palette.
	const struct {
		const char *style;
		const char *color;
	} styles[] = {
		{ Color_BBLUE, pal->fname },
		{ "\x1b[48;5;234m", pal->widget_bg },
		{ "\x1b[48;5;22m", pal->widget_bg },
		{ "\x1b[48;5;52m", pal->widget_bg },
		{ Color_WHITE, pal->reg },
		{ Color_YELLOW, code.string },
		{ Color_CYAN, code.cpp },
		{ Color_GREEN, code.comment },
		{ Color_BLUE, code.number },
		{ Color_MAGENTA, code.keyword },
		{ Color_RED, code.types },
	};
	while (text && *text) {
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (styles); i++) {
			if (r_str_startswith (text, styles[i].style)) {
				r_strbuf_append (out, styles[i].color);
				text += strlen (styles[i].style);
				break;
			}
		}
		if (i == R_ARRAY_SIZE (styles)) {
			r_strbuf_append_n (out, text++, 1);
		}
	}
}

static void slide_markdown(RCore *core, RStrBuf *out, const char *text, int width, bool title) {
	RMarkdownOptions options = {
		.color = r_config_get_i (core->config, "scr.color") > 0,
		.utf8 = r_config_get_b (core->config, "scr.utf8"),
		.utf8_curvy = r_config_get_b (core->config, "scr.utf8.curvy"),
		.slide_titles = title,
	};
	char *rendered = r_str_md2txt_ex (text, &options, R_MAX (1, width), true);
	slide_theme (core, out, rendered);
	free (rendered);
}

static void slide_flush(RCore *core, RStrBuf *out, RStrBuf *body, int width) {
	if (!r_strbuf_is_empty (body)) {
		slide_markdown (core, out, r_strbuf_get (body), width, false);
		r_strbuf_set (body, "");
	}
}

static void slide_collect(RStrBuf *out, size_t *scanned, int *x, int *y, const char *word, RList *hits, int page) {
	if (!hits) {
		return;
	}
	size_t end = r_strbuf_length (out);
	if (end == *scanned) {
		return;
	}
	char *text = strdup (r_strbuf_get (out) + *scanned);
	*scanned = end;
	if (!text) {
		return;
	}
	r_str_ansi_strip (text);
	const char *p = text;
	size_t length = word? strlen (word): 0;
	const char *next = length? strstr (p, word): NULL;
	for (; *p; p++) {
		if (p == next) {
			SlidesMatch *hit = R_NEW (SlidesMatch);
			SlidesMatch *previous = r_list_last (hits);
			*hit = (SlidesMatch) { page, *x, *y, previous && previous->page == page? previous->ordinal + 1: 0 };
			r_list_append (hits, hit);
			next = strstr (p + length, word);
		}
		if (*p == '\n') {
			*x = 0;
			(*y)++;
		} else if (((ut8)*p & 0xc0) != 0x80) {
			(*x)++;
		}
	}
	free (text);
}

static char *slide_text(SlidesState *state, RCore *core, RList *list, int page, int width, const char *word, RList *hits) {
	RCons *cons = core->cons;
	size_t scanned = 0;
	int x = 0, y = 0;
	int count = 0;
	int notch = R_MAX (1, r_config_get_i (core->config, "scr.notch"));
	bool markdown = false;
	SlidesFence fence = {0};
	RListIter *iter;
	const char *line;
	RStrBuf *sb = r_strbuf_new (NULL);
	RStrBuf *body = r_strbuf_new (NULL);
	r_strbuf_pad (sb, '\n', notch);
	r_list_foreach (list, iter, line) {
		const char *s = r_str_trim_head_ro (line);
		bool literal = fence.marker != 0;
		bool delimiter = slide_fence (&fence, s);
		if (!literal && !delimiter && r_str_startswith (s, "# ")) {
			if (++count > page) {
				break;
			}
		}
		if (count != page) {
			continue;
		}
		if (literal || delimiter) {
			if (markdown) {
				r_strbuf_appendf (body, "%s\n", line);
			} else if (!delimiter) {
				r_strbuf_appendf (sb, "     %s\n", line);
			}
			slide_collect (sb, &scanned, &x, &y, word, hits, page);
			continue;
		}
		size_t length = strlen (s);
		size_t dashes = strspn (s, "-");
		bool rule = markdown && dashes >= 3 && !s[dashes];
		bool directive = !rule && r_str_startswith (s, "--");
		bool command = length >= 2 && s[0] == '`' && s[1] != '`'
			&& s[length - 1] == '`' && !memchr (s + 1, '`', length - 2);
		if (command || directive || *s == '#') {
			slide_flush (core, sb, body, width);
		}
		if (command) {
			slide_collect (sb, &scanned, &x, &y, word, hits, page);
			if (!state) {
				continue;
			}
			char *cmd = r_str_ndup (s + 1, length - 2);
			char *res = r_core_cmd_str (core, cmd);
			r_strbuf_append (sb, res);
			free (res);
			free (cmd);
			slide_collect (sb, &scanned, &x, &y, NULL, hits, page);
		} else if (!strcmp (s, "--markdown")) {
			markdown = true;
		} else if (!strcmp (s, "--markdown=false")) {
			markdown = false;
		} else if (r_str_startswith (s, "--color=")) {
			const char *value = s + strlen ("--color=");
			if (*value) {
				RColor palette_color;
				char *color;
				if (*value == '@') {
					palette_color = r_cons_pal_get (cons, value + 1);
					color = r_cons_rgb_str (cons, NULL, 0, &palette_color);
				} else {
					color = r_cons_pal_parse (cons, value, NULL);
				}
				r_strbuf_append (sb, color);
				free (color);
			} else {
				r_strbuf_append (sb, Color_RESET);
			}
		} else if (r_str_startswith (s, "--gotokey:")) {
			const char *binding = s + strlen ("--gotokey:");
			if (state && binding[0] && binding[1] == ':') {
				ut8 key = (ut8)binding[0];
				free (state->keys[key]);
				state->keys[key] = binding[2]? strdup (binding + 2): NULL;
			}
		} else if (directive) {
			// Directives are hidden from the audience.
		} else if (*s == '#') {
			if (word) {
				while (*s == '#') {
					s++;
				}
				r_strbuf_appendf (sb, "  %s\n", r_str_trim_head_ro (s));
			} else {
				slide_heading (core, sb, s, iter->n, width);
			}
		} else if (markdown) {
			r_strbuf_appendf (body, "%s\n", line);
		} else {
			char *trimmed = r_str_trim_dup (s);
			r_strbuf_appendf (sb, "     %s\n", trimmed);
			free (trimmed);
		}
		slide_collect (sb, &scanned, &x, &y, word, hits, page);
	}
	slide_flush (core, sb, body, width);
	slide_collect (sb, &scanned, &x, &y, word, hits, page);
	r_strbuf_free (body);
	if (r_config_get_i (core->config, "scr.color") > 0) {
		r_strbuf_append (sb, Color_RESET);
	}
	return r_strbuf_drain (sb);
}

static void slide_search_index(SlidesSearch *search, RCore *core, RList *list, int total, int mode) {
	r_list_free (search->hits);
	search->hits = search->word? r_list_newf (free): NULL;
	search->current = 0;
	search->focus = false;
	if (search->word) {
		search->width = R_MAX (1, r_cons_get_size (core->cons, NULL) / mode);
		int page;
		for (page = 1; page <= total; page++) {
			free (slide_text (NULL, core, list, page, search->width, search->word, search->hits));
		}
	}
}

static void slide_search_next(SlidesSearch *search, int *page, int step) {
	int count = search->hits? r_list_length (search->hits): 0;
	if (count) {
		search->current = (search->current + count + step) % count;
		SlidesMatch *hit = r_list_get_n (search->hits, search->current);
		*page = hit->page;
		search->focus = true;
	}
}

static void render(SlidesState *state, RCore *core, RList *list, int mode, int page, int *scroll_x, int *scroll_y, SlidesSearch *search) {
	RCons *cons = core->cons;
	int h, columns = r_cons_get_size (cons, &h);
	int offset = mode == 2? columns / 2: 0;
	int width = R_MAX (1, mode == 1? columns: mode == 2? columns - offset: columns / 2);
	int sx = *scroll_x, sy = *scroll_y;
	RList *hits = search->focus? r_list_newf (free): NULL;
	char *output = slide_text (state, core, list, page, width, search->word, hits);
	SlidesMatch *selected = search->focus && search->hits? r_list_get_n (search->hits, search->current): NULL;
	if (selected && selected->page == page) {
		SlidesMatch *hit = r_list_get_n (hits, selected->ordinal);
		if (hit) {
			sx = hit->x >= sx && hit->x + (int)r_str_len_utf8 (search->word) <= sx + width? sx: hit->x;
			sy = hit->y >= sy && hit->y < sy + h - 1? sy: hit->y;
			*scroll_x = sx;
			*scroll_y = sy;
		}
	}
	r_list_free (hits);
	sx = R_MAX (0, sx);
	sy = R_MAX (0, sy);
	char *cropped = r_str_ansi_crop (output, sx, sy, (ut32)sx + width, (ut32)sy + R_MAX (0, h - 1));
	free (output);
	if (cropped) {
		if (offset) {
			char *prefix = r_str_pad (NULL, 0, ' ', offset);
			char *positioned = r_str_prefix_all (cropped, prefix);
			r_cons_print (cons, positioned);
			free (positioned);
			free (prefix);
		} else {
			r_cons_print (cons, cropped);
		}
		free (cropped);
	}
}

static void render_page_index(RCore *core, int page, int total, SlidesSearch *search) {
	R_RETURN_IF_FAIL (page >= 0 && total >= 0);
	int height;
	int width = R_MAX (1, r_cons_get_size (core->cons, &height));
	char *index = search->word? r_str_newf ("[%d/%d] %d/%d",
		r_list_empty (search->hits)? 0: search->current + 1, r_list_length (search->hits), page, total):
		r_str_newf ("%d/%d", page, total);
	if (!index) {
		return;
	}
	int length = strlen (index);
	const char *visible = index + R_MAX (0, length - width);
	length = R_MIN (length, width);
	bool color = r_config_get_i (core->config, "scr.color") > 0;
	RConsPrintablePalette *pal = &core->cons->context->pal;
	r_cons_gotoxy (core->cons, width - length + 1, R_MAX (1, height));
	r_cons_printf (core->cons, "%s%s%s%s", color? pal->prompt: "",
		color? pal->widget_bg: "", visible, color? Color_RESET: "");
	free (index);
}

static void slides_refresh(void *user) {
	SlidesView *view = user;
	RCons *cons = view->core->cons;
	RConsEvent resize = cons->event_resize;
	cons->event_resize = NULL;
	if (view->search->word && view->search->width != R_MAX (1, r_cons_get_size (cons, NULL) / view->mode)) {
		int current = view->search->current;
		slide_search_index (view->search, view->core, view->list, view->total_pages, view->mode);
		view->search->current = R_MIN (current, R_MAX (0, (int)r_list_length (view->search->hits) - 1));
		slide_search_next (view->search, &view->page, 0);
	}
	clearkeys (view->state);
	r_cons_clear00 (cons);
	if (view->mode == 2) {
		render (view->state, view->core, view->list, 2, view->page + 1, &view->sx, &view->sy, view->search);
	}
	r_cons_gotoxy (cons, 0, 0);
	render (view->state, view->core, view->list, view->mode == 2? 0: 1, view->page, &view->sx, &view->sy, view->search);
	render_page_index (view->core, view->page, view->total_pages, view->search);
	r_cons_flush (cons);
	view->search->focus = false;
	cons->event_resize = resize;
}

R_API void r_core_visual_slides(RCore *core, const char *file) {
	R_RETURN_IF_FAIL (core && file);
	const bool interactive = r_config_get_b (core->config, "scr.interactive");
	if (!interactive) {
		R_LOG_ERROR ("Requires scr.interactive=true");
		return;
	}
	if (!*file) {
		return;
	}
	char *data = r_file_slurp (file, NULL);
	if (!data) {
		R_LOG_ERROR ("Cannot open file");
		return;
	}
	RList *list = slides_load (data);

	const bool mouse = core->cons->mouse;
	r_config_set_b (core->config, "scr.interactive", false);
	bool having_fun = true;
	int ch;
	int page = 1;
	int mode = 1;
	int sx = 0;
	int sy = 0;
	r_cons_set_raw (core->cons, 1);
	r_cons_show_cursor (core->cons, false);
	int total_pages = count_pages (list);
	SlidesState state = {0};
	SlidesSearch search = {0};
	while (having_fun) {
		if (page > total_pages) {
			page = total_pages;
		}
		SlidesView view = { &state, core, list, mode, page, sx, sy, total_pages, &search };
		slides_refresh (&view);
		r_cons_set_raw (core->cons, true);
		r_cons_enable_mouse (core->cons, r_config_get_b (core->config, "scr.wheel"));
		RConsEvent resize = core->cons->event_resize;
		void *event_data = core->cons->event_data;
		core->cons->event_resize = NULL;
		core->cons->event_data = &view;
		core->cons->event_resize = slides_refresh;
		ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
		core->cons->event_resize = NULL;
		core->cons->event_data = event_data;
		core->cons->event_resize = resize;
		page = view.page;
		sx = view.sx;
		sy = view.sy;
		if (ch < 0) {
			break;
		}
		switch (ch) {
		case 'J':
		case 'K':
			{
				int height;
				r_cons_get_size (core->cons, &height);
				int step = R_MAX (1, height - 1);
				sy = (ch == 'J')? R_MIN (sy, INT_MAX - step) + step: R_MAX (0, sy - step);
			}
			break;
		case 'j':
			sy++;
			break;
		case 'k':
			sy--;
			if (sy < 0) {
				sy = 0;
			}
			break;
		case 'l':
			sx++;
			break;
		case 'h':
			sx--;
			if (sx < 0) {
				sx = 0;
			}
			break;
		case '1':
			mode = 1;
			break;
		case '2':
			mode = 2;
			break;
		case 'q':
			if (search.word) {
				R_FREE (search.word);
				r_list_free (search.hits);
				search.hits = NULL;
				search.focus = false;
				r_config_set (core->config, "scr.highlight", "");
				break;
			}
			having_fun = false;
			break;
		case ' ':
		case 'n':
		case 'P':
			if (search.word) {
				slide_search_next (&search, &page, 1);
				break;
			}
			page += mode;
			sx = sy = 0;
			break;
		case 'p':
		case 'N':
			if (search.word) {
				slide_search_next (&search, &page, -1);
				break;
			}
			sx = sy = 0;
			page -= mode;
			if (page < 1) {
				page = 1;
			}
			break;
		case '?':
			r_cons_enable_mouse (core->cons, false);
			eprintf ("Keys:\n");
			eprintf (" np   = next/prev slide\n");
			eprintf (" hjkl = scroll current slide left/down/up/right\n");
			eprintf (" JK   = scroll current slide one screen down/up (PgDn/PgUp)\n");
			eprintf (" /    = search slide text (np navigate matches)\n");
			eprintf (" q    = cancel search or quit the slides\n");
			eprintf (" e    = edit the current slide with cfg.editor\n");
			eprintf (" 12   = show 1 or two pages\n");
			eprintf (" R/r  = next/previous color theme (ecn/ecp)\n");
			eprintf (" ^R   = reload the slides\n");
			eprintf (" :    = enter command\n");
			if (r_cons_any_key (core->cons, NULL) < 0) {
				having_fun = false;
			}
			break;
		case 'e':
		case '!':
			{
				r_cons_enable_mouse (core->cons, false);
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, false);
				r_config_set_b (core->config, "scr.interactive", true);
				free (r_cons_editor (core->cons, file, NULL, slide_line (list, page), NULL));
				char *ndata = r_file_slurp (file, NULL);
				if (ndata) {
					r_list_free (list);
					free (data);
					data = ndata;
					list = slides_load (data);
					total_pages = count_pages (list);
					slide_search_index (&search, core, list, total_pages, mode);
					slide_search_next (&search, &page, 0);
				}
				r_config_set_b (core->config, "scr.interactive", false);
				r_cons_show_cursor (core->cons, false);
			}
			break;
		case 'R':
			r_core_cmd0 (core, "ecn");
			break;
		case 'r':
			r_core_cmd0 (core, "ecp");
			break;
		case 0x12: // Ctrl-R: reload
			{
				char *ndata = r_file_slurp (file, NULL);
				if (ndata) {
					r_list_free (list);
					free (data);
					data = ndata;
					list = slides_load (data);
					total_pages = count_pages (list);
					slide_search_index (&search, core, list, total_pages, mode);
					slide_search_next (&search, &page, 0);
				}
			}
			break;
		case '/':
			{
				char buf[1024] = {0};
				char *prompt = r_line_get_prompt (core->cons->line);
				r_cons_enable_mouse (core->cons, false);
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, false);
				int height;
				r_cons_get_size (core->cons, &height);
				r_cons_gotoxy (core->cons, 1, R_MAX (1, height));
				r_cons_clear_line (core->cons, false, true);
				r_line_set_prompt (core->cons->line, "/");
				int result = r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL);
				r_line_set_prompt (core->cons->line, prompt);
				free (prompt);
				r_cons_show_cursor (core->cons, false);
				if (result < 0) {
					having_fun = false;
				} else {
					free (search.word);
					search.word = *buf? strdup (buf): NULL;
					r_config_set (core->config, "scr.highlight", buf);
					slide_search_index (&search, core, list, total_pages, mode);
					slide_search_next (&search, &page, 0);
					sx = sy = 0;
				}
			}
			break;
		case ':':
			{
				char *prompt = r_line_get_prompt (core->cons->line);
				if (!prompt) {
					break;
				}
				r_cons_enable_mouse (core->cons, false);
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, false);
				r_cons_flush (core->cons);
				while (1) {
					char cmd[1024];
					*cmd = 0;
					r_line_set_prompt (core->cons->line, ":> ");
					if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
						having_fun = false;
						break;
					}
					r_core_cmd0 (core, cmd);
					if (!cmd[0]) {
						break;
					}
					r_cons_flush (core->cons);
				}
				r_line_set_prompt (core->cons->line, prompt);
				free (prompt);
				r_cons_show_cursor (core->cons, false);
				r_cons_set_raw (core->cons, true);
				r_cons_clear (core->cons);
			}
			break;
		default:
			page = gotokey (&state, list, ch, page);
			break;
		}
	}
	r_cons_set_raw (core->cons, 0);
	r_cons_show_cursor (core->cons, true);
	r_cons_enable_mouse (core->cons, mouse);
	clearkeys (&state);
	if (search.word) {
		r_config_set (core->config, "scr.highlight", "");
	}
	free (search.word);
	r_list_free (search.hits);
	r_list_free (list);
	free (data);
	r_config_set_b (core->config, "scr.interactive", interactive);
	r_cons_clear00 (core->cons);
}
