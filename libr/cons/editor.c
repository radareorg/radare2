/* radare - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>

typedef struct {
	char *path;
	char prompt[32];
	RList *lines;
	int n; // current line
} RConsEditor;

/* TODO: remove global vars */
static R_TH_LOCAL RConsEditor G = {0};

static void r_cons_editor_init(void) {
	memset (&G, 0, sizeof (G));
	G.lines = r_list_newf (free);
}

static void setprompt(RCons *cons) {
	snprintf (G.prompt, sizeof (G.prompt), "(%d/%d): ", G.n, r_list_length (G.lines));
	r_line_set_prompt (cons->line, G.prompt);
}

static void setcurline(RCons *cons) {
	setprompt (cons);
	const char *nline = r_list_get_n (G.lines, G.n);
	const char *curline = r_str_get (nline);
	RLine *line = cons->line;
	r_str_ncpy (line->buffer.data, curline, sizeof (line->buffer.data) - 1);
	line->buffer.data[sizeof (line->buffer.data) - 1] = '\0';
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	line->contents = (char*)curline;
}

static void emptyline(RCons *cons, const char *str) {
	if (G.n == r_list_length (G.lines)) {
		// r_list_append (G.lines, strdup (str));
	} else {
		RListIter *iter = r_list_get_nth (G.lines, G.n);
		if (iter) {
			r_list_delete (G.lines, iter);
		}
	}
	setprompt (cons);
	setcurline (cons);
}

static void saveline(RCons *cons, const char *str) {
	if (G.n == r_list_length (G.lines)) {
		r_list_append (G.lines, strdup (str));
	} else {
		if (str) {
			RListIter *iter = r_list_get_nth (G.lines, G.n);
			if (iter) {
				r_list_delete (G.lines, iter);
			}
			r_list_insert (G.lines, G.n, strdup (str));
		} else {
			r_list_insert (G.lines, G.n, strdup (""));
		}
	}
	setprompt (cons);
	setcurline (cons);
}

static int up(RCons *cons, void *n) {
	R_LOG_DEBUG ("up");
	if (G.n > 0) {
		G.n--;
	}
	setcurline (cons);
	return 0;
}

static int down(RCons *cons, void *n) {
	R_LOG_DEBUG ("down");
	if (G.n < r_list_length (G.lines)) {
		G.n++;
	}
	setcurline (cons);
	return 0;
}

R_API char *r_cons_editor(RCons *cons, const char *file, const char *str) {
	// bool visual = false; // TODO: should be an argument
	if (cons->cb_editor) {
		return cons->cb_editor (cons->line->user, file, str);
	}
	r_cons_editor_init ();
	if (R_STR_ISNOTEMPTY (file)) {
		G.path = strdup (file);
		size_t sz = 0;
		char *data = r_file_slurp (file, &sz);
		r_str_trim (data);
		if (*data) {
			r_list_free (G.lines);
			G.lines = r_str_split_list (data, "\n", 0);
		}
		free (data);
		if (!G.lines) {
			R_LOG_ERROR ("Failed to load '%s'", file);
			R_FREE (G.path);
			return NULL;
		}
	}
	R_LOG_INFO ("Loaded %d lines. Use ^D or '.' to save and quit", r_list_length (G.lines));
	RLine *line = cons->line;
	line->hist_up = up;
	line->hist_down = down;
	line->contents = line->buffer.data;
	cons->echo = false;
	for (;;) {
		setcurline (cons);
		const char *line = r_line_readline (cons);
		if (R_STR_ISNOTEMPTY (line)) {
			r_str_trim ((char *)line);
			if (!strcmp (line, ".")) {
				break;
			}
			if (r_str_endswith (line, "\\")) {
				((char *)line)[strlen (line) - 1] = 0;
				saveline (cons, line);
				setcurline (cons);
				G.n++;
				saveline (cons, NULL);
				setcurline (cons);
			} else {
				saveline (cons, *line? line: "\\");
				G.n++;
			}
		} else {
			if (!line) {
				break;
			}
			if (G.n == r_list_length (G.lines)) {
				RListIter *iter;
				int n = 0;
				r_list_foreach (G.lines, iter, line) {
					eprintf ("%2d| %s\n", n++, line);
				}
			} else {
				emptyline (cons, line);
			}
		}
	}
	if (!r_cons_yesno ('y', "Save? (Y/n)")) {
		r_list_free (G.lines);
		return NULL;
	}
	char *s = r_str_list_join (G.lines, "\n");
	r_str_trim (s);
	line->hist_up = NULL;
	line->hist_down = NULL;
	line->contents = NULL;
	r_list_free (G.lines);
	if (file) {
		r_file_dump (file, (const ut8*)s, -1, 0);
	}
	return s;
}
