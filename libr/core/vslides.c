/* radare - LGPL - Copyright 2021-2025 - pancake */

#include <r_core.h>

typedef struct slides_state_t {
	char *keys[256];
} SlidesState;

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

static void render(SlidesState *state, RCore *core, RList *list, int mode, int page, int sx, int sy) {
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
	r_list_foreach (list, iter, s) {
		if (r_str_startswith (s, "# ")) {
			count++;
		}
		if (count == page) {
			if (*s == '`') {
				char *cmd = r_str_ndup (s + 1, strlen (s) -2);
				char *res = r_core_cmd_str (core, cmd);
				// r_cons_printf ("%s", res);
				r_strbuf_append (sb, res);
				free (res);
				free (cmd);
			} else if (r_str_startswith (s, "--color=")) {
				char *kv = strdup (s + strlen ("--color="));
				if (*kv) {
					char *k = r_cons_pal_parse (kv, NULL);
					r_strbuf_append (sb, k);
					free (k);
				} else {
					r_strbuf_append (sb, Color_RESET);
				}
				free (kv);
			} else if (r_str_startswith (s, "--gotokey:")) {
				char *kv = strdup (s + strlen ("--gotokey:"));
				if (kv[0] && kv[1]) {
					kv[1] = 0;
					int k = kv[0];
					R_FREE (state->keys[k]);
					if (kv[2]) {
						state->keys[k] = strdup (kv + 2);
					}
				}
				free (kv);
			} else if (!strncmp (s, "--", 2)) {
				// directive, do not print

			} else if (*s == '#') {
				char *ss = r_str_ss (s, 0, 0);
				r_strbuf_append (sb, ss);
				free (ss);
			} else {
				r_strbuf_appendf (sb, "     %s\n", s);
			}
		}
	}
	char *o = r_strbuf_drain (sb);
	char *oo = r_str_newf ("%s%s", r_str_pad ('\n', notch), o);
	free (o);
	o = oo;
	int h, w = r_cons_get_size (&h);
	if (mode == 2) {
		w /= 2;
		char *o2 = r_str_ansi_crop (o, sx, sy, w, h);
		const char *prefix = r_str_pad (' ', w);
		char *no = r_str_prefix_all (o2, prefix);
		free (o);
		free (o2);
		o = no;
		r_cons_print (o);
	} else {
		char *no = r_str_ansi_crop (o, sx, sy, w, h);
		r_cons_print (no);
		free (no);
	}
	free (o);
}

static void render_title(int page, int mode, int total) {
	R_RETURN_IF_FAIL (page >= 0 && mode >= 0 && total >= 0);
	r_cons_gotoxy (0, 0);
	r_cons_printf ("%s%s%s\r [r2slides] [%s:%d/%d]",
			Color_BLACK, Color_BGYELLOW, R_CONS_CLEAR_LINE,
			(mode == 2)? "pages": "page", page, total);
}

R_API void r_core_visual_slides(RCore *core, const char *file) {
	R_RETURN_IF_FAIL (core && file);
	if (!r_config_get_b (core->config, "scr.interactive")) {
		R_LOG_ERROR ("Requires scr.interactive=true");
		return;
	}
	r_config_set_b (core->config, "scr.interactive", false);
	bool having_fun = true;
	if (!*file) {
		return;
	}
	char *data = r_file_slurp (file, NULL);
	if (!data) {
		R_LOG_ERROR ("Cannot open file");
		return;
	}
	RList *list = r_str_split_list (data, "\n", 0);

	int ch;
	int page = 1;
	int mode = 1;
	int sx = 0;
	int sy = 0;
	r_kons_set_raw (core->cons, 1);
	r_cons_show_cursor (false);
	r_kons_enable_mouse (core->cons, false);
	int total_pages = count_pages (list);
	SlidesState state = {0};
	while (having_fun) {
		if (page > total_pages) {
			page = total_pages;
		}
		clearkeys (&state);
		r_cons_clear00 ();
		if (mode == 2) {
			render (&state, core, list, 2, page + 1, sx, sy);
		}
		r_cons_gotoxy (0, 0);
		render (&state, core, list, 1, page, sx, sy);
		render_title (page, mode, total_pages);
		r_cons_flush ();
		r_cons_set_raw (true);
		ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
		switch (ch) {
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
			if (sy < 0) {
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
			eprintf ("Keys:\n");
			eprintf (" np   = next/prev slide\n");
			eprintf (" hjkl = scroll current slide left/down/up/right\n");
			eprintf (" q    = quit the slides\n");
			eprintf (" e    = open vim to edit the current slide\n");
			eprintf (" 12   = show 1 or two pages\n");
			eprintf (" :    = enter command\n");
			r_cons_any_key (NULL);
			break;
		case 'e':
		case '!':
			//
			{
				r_config_set_b (core->config, "scr.interactive", true);
				r_core_cmdf (core, "vim %s", file);
				char *ndata = r_file_slurp (file, NULL);
				if (ndata) {
					r_list_free (list);
					free (data);
					data = ndata;
					list = r_str_split_list (data, "\n", 0);
					total_pages = count_pages (list);
				}
				r_config_set_b (core->config, "scr.interactive", false);
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
			r_cons_show_cursor (true);
			r_cons_set_raw (false);
			r_kons_flush (core->cons);
			while (1) {
				char cmd[1024];
				*cmd = 0;
				r_line_set_prompt (core->cons, ":> ");
				if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				r_core_cmd0 (core, cmd);
				if (!cmd[0]) {
					break;
				}
				r_cons_flush ();
			}
			r_cons_show_cursor (false);
			r_cons_set_raw (true);
			r_cons_clear ();
			break;
		default:
			page = gotokey (&state, list, ch, page);
			break;
		}
	}
	r_cons_set_raw (0);
	r_cons_show_cursor (true);
	r_list_free (list);
	free (data);
	r_config_set_b (core->config, "scr.interactive", true);
}
