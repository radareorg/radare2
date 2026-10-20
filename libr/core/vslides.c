/* radare - LGPL - Copyright 2021-2025 - pancake */

#include <r_core.h>

typedef struct slides_state_t {
	char *keys[256];
} SlidesState;

typedef struct slides_view_t {
	SlidesState *state;
	RCore *core;
	RList *list;
	int mode;
	int page;
	int sx;
	int sy;
	int total_pages;
} SlidesView;

static void clearkeys(SlidesState *state) {
	int i;
	for (i = 0; i < 256; i++) {
		free (state->keys[i]);
	}
	memset (state, 0, sizeof (SlidesState));
}

static int findpage(RList *list, const char *pagename) {
	int count = 0;
	RListIter *iter;
	char *s;
	r_list_foreach (list, iter, s) {
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
	char *s;
	RListIter *iter;
	r_list_foreach (list, iter, s) {
		if (r_str_startswith (s, "# ")) {
			pages++;
		}
	}
	return pages;
}

static int slide_line(RList *list, int page) {
	int line = 1;
	int current_page = 0;
	RListIter *iter;
	const char *text;
	r_list_foreach (list, iter, text) {
		if (r_str_startswith (text, "# ") && ++current_page == page) {
			return line;
		}
		line++;
	}
	return 1;
}

static void render(SlidesState *state, RCore *core, RList *list, int mode, int page, int sx, int sy) {
	RCons *cons = core->cons;
	char *s;
	if (page < 0) {
		page = 0;
	}
	if (sx < 0) {
		sx = 0;
	}
	if (sy < 0) {
		sy = 0;
	}
	int count = 0;
	int notch = r_config_get_i (core->config, "scr.notch");
	if (notch < 1) {
		notch = 1;
	}
	RListIter *iter;
	RStrBuf *sb = r_strbuf_new (NULL);
	r_strbuf_pad (sb, '\n', notch);
	r_list_foreach (list, iter, s) {
		if (r_str_startswith (s, "# ")) {
			count++;
		}
		if (count == page) {
			if (*s == '`') {
				char *cmd = r_str_ndup (s + 1, strlen (s) -2);
				char *res = r_core_cmd_str (core, cmd);
				r_strbuf_append (sb, res);
				free (res);
				free (cmd);
			} else if (r_str_startswith (s, "--color=")) {
				char *kv = strdup (s + strlen ("--color="));
				if (*kv) {
					char *k = r_cons_pal_parse (core->cons, kv, NULL);
					r_strbuf_append (sb, k);
					free (k);
				} else {
					r_strbuf_append (sb, Color_RESET);
				}
				free (kv);
			} else if (r_str_startswith (s, "--gotokey:")) {
				char *kv = strdup (s + strlen ("--gotokey:"));
				if (kv && kv[0] && kv[1]) {
					kv[1] = 0;
					int k = kv[0];
					free (state->keys[k]);
					if (kv[2]) {
						state->keys[k] = strdup (kv + 2);
					} else {
						state->keys[k] = NULL;
					}
				}
				free (kv);
			} else if (r_str_startswith (s, "--")) {
				// directive, do not print
			} else if (*s == '#') {
				char *ss = r_core_md2txt (core, s, true);
				r_strbuf_append (sb, ss);
				free (ss);
			} else {
				r_strbuf_appendf (sb, "     %s\n", s);
			}
		}
	}
	char *o = r_strbuf_drain (sb);
	int h, w = r_cons_get_size (core->cons, &h);
	if (mode == 2) {
		w /= 2;
		char *o2 = r_str_ansi_crop (o, sx, sy, (ut32)sx + w, (ut32)sy + h);
		char *prefix = r_str_pad (NULL, 0, ' ', w);
		char *no = r_str_prefix_all (o2, prefix);
		free (prefix);
		free (o2);
		free (o);
		o = no;
		r_cons_print (cons, o);
	} else {
		char *no = r_str_ansi_crop (o, sx, sy, (ut32)sx + w, (ut32)sy + h);
		if (no) {
			r_cons_print (cons, no);
			free (no);
		}
		free (o);
		o = NULL;
	}
}

static void render_title(RCore *core, int page, int mode, int total) {
	R_RETURN_IF_FAIL (page >= 0 && mode >= 0 && total >= 0);
	r_cons_gotoxy (core->cons, 0, 0);
	r_cons_printf (core->cons, "%s%s%s\r [r2slides] [%s:%d/%d]",
			Color_BLACK, Color_BGYELLOW, R_CONS_CLEAR_LINE,
			(mode == 2)? "pages": "page", page, total);
}

static void slides_refresh(void *user) {
	SlidesView *view = user;
	RCons *cons = view->core->cons;
	RConsEvent resize = cons->event_resize;
	cons->event_resize = NULL;
	clearkeys (view->state);
	r_cons_clear00 (cons);
	if (view->mode == 2) {
		render (view->state, view->core, view->list, 2, view->page + 1, view->sx, view->sy);
	}
	r_cons_gotoxy (cons, 0, 0);
	render (view->state, view->core, view->list, 1, view->page, view->sx, view->sy);
	render_title (view->core, view->page, view->mode, view->total_pages);
	r_cons_flush (cons);
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
	RList *list = r_str_split_list (data, "\n", 0);

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
	while (having_fun) {
		if (page > total_pages) {
			page = total_pages;
		}
		SlidesView view = { &state, core, list, mode, page, sx, sy, total_pages };
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
			having_fun = false;
			break;
		case ' ':
		case 'n':
		case 'P':
			page += mode;
			sx = sy = 0;
			break;
		case 'p':
		case 'N':
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
			eprintf (" q    = quit the slides\n");
			eprintf (" e    = edit the current slide with cfg.editor\n");
			eprintf (" 12   = show 1 or two pages\n");
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
					list = r_str_split_list (data, "\n", 0);
					total_pages = count_pages (list);
				}
				r_config_set_b (core->config, "scr.interactive", false);
				r_cons_show_cursor (core->cons, false);
			}
			break;
		case 'r': // reload
		case 'R':
			{
				char *ndata = r_file_slurp (file, NULL);
				if (ndata) {
					r_list_free (list);
					free (data);
					data = ndata;
					list = r_str_split_list (data, "\n", 0);
					total_pages = count_pages (list);
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
	r_list_free (list);
	free (data);
	r_config_set_b (core->config, "scr.interactive", interactive);
	r_cons_clear00 (core->cons);
}
