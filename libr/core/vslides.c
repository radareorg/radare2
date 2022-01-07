/* radare - LGPL - Copyright 2021 - pancake */

#include <r_core.h>

static char *keys[256] = {0};

static void clearkeys(void) {
	int i;
	for (i = 0; i < 256; i++) {
		free (keys[i]);
		keys[i] = NULL;
	}
}

static int findpage(RList *list, const char *pagename) {
	int count = 0;
	RListIter *iter;
	char *s;
	r_list_foreach (list, iter, s) {
		if (!strncmp (s, "# ", 2)) {
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

static int gotokey(RList *list, int ch, int page) {
	if (keys[ch]) {
		int npage = findpage (list, keys[ch]);
		if (npage != -1) {
			return npage;
		}
	}
	return page;
}

static void render(RCore *core, RList *list, int page) {
	char *s;
	if (page < 0) {
		page = 0;
	}
	int count = 0;
	RListIter *iter;
	r_list_foreach (list, iter, s) {
		if (!strncmp (s, "# ", 2)) {
			count++;
		}
		if (count == page) {
			if (*s == '`') {
				char *cmd = r_str_ndup (s + 1, strlen (s) -2);
				char *res = r_core_cmd_str (core, cmd);
				r_cons_printf ("%s", res);
				free (res);
				free (cmd);
			} else if (r_str_startswith (s, "--gotokey:")) {
				char *kv = strdup (s + strlen ("--gotokey:"));
				if (kv[0] && kv[1]) {
					kv[1] = 0;
					int k = kv[0];
					R_FREE (keys[k]);
					if (kv[2]) {
						keys[k] = strdup (kv + 2);
					}
				}
				free (kv);
			} else if (!strncmp (s, "--", 2)) {
				// directive, do not print
				
			} else if (*s == '#') {
				char *ss = r_str_ss (s, 0, 0);
				r_cons_printf ("%s\n", ss);
				free (ss);
			} else {
				r_cons_printf ("     %s\n", s);
			}
		}
	}
}

R_API void r_core_visual_slides(RCore *core, const char *file) {
	bool having_fun = true;
	r_return_if_fail (core && file);
	if (!*file) {
		return;
	}
	char *data = r_file_slurp (file, NULL);
	if (!data) {
		eprintf ("Cannot open file.\n");
		return;
	}
	RList *list = r_str_split_list (data, "\n", 0);

	int ch;
	int page = 1;
	while (having_fun) {
		clearkeys ();
		r_cons_clear00 ();
		render (core, list, page);
		r_cons_flush ();
		r_cons_enable_mouse (false);
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case 'q':
			having_fun = false;
			break;
		case ' ':
		case 'n':
			page++;
			break;
		case 'p':
			page--;
			if (page < 1) {
				page = 1;
			}
			break;
		case '!':
			//
			{
				r_core_cmdf (core, "vim %s", file);
				char *ndata = r_file_slurp (file, NULL);
				if (ndata) {
					r_list_free (list);
					free (data);
					data = ndata;
					list = r_str_split_list (data, "\n", 0);
				}
			}
			break;
		case ':':
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			while (1) {
				char cmd[1024];
				*cmd = 0;
				r_line_set_prompt (":> ");
				if (r_cons_fgets (cmd, sizeof (cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				r_core_cmd0 (core, cmd);
				if (!cmd[0]) {
					break;
				}
				r_cons_flush ();
			}
			r_cons_show_cursor (false);
			r_cons_set_raw (1);
			r_cons_clear ();
			break;
		default:
			page = gotokey (list, ch, page);
			break;
		}
	}
	r_list_free (list);
	free (data);
}
