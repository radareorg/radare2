/* radare - LGPL - Copyright 2008-2024 - pancake */

#include <r_cons.h>
#define I r_cons_singleton ()

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

static void setprompt(void) {
	snprintf (G.prompt, sizeof (G.prompt), "(%d/%d): ", G.n, r_list_length (G.lines));
	r_line_set_prompt (G.prompt);
}

static void setcurline(void) {
	setprompt ();
	const char *nline = r_list_get_n (G.lines, G.n);
	const char *curline = r_str_get (nline);
#if 1
	r_str_ncpy (I->line->buffer.data, curline, sizeof (I->line->buffer.data) - 1);
	I->line->buffer.data[sizeof (I->line->buffer.data) - 1] = '\0';
	I->line->buffer.index = I->line->buffer.length = strlen (I->line->buffer.data);
#endif
	I->line->contents = (char*)curline;
}

static void emptyline(const char *str) {
	if (G.n == r_list_length (G.lines)) {
		// r_list_append (G.lines, strdup (str));
	} else {
		RListIter *iter = r_list_get_nth (G.lines, G.n);
		if (iter) {
			r_list_delete (G.lines, iter);
		}
	}
	setprompt ();
	setcurline ();
}

static void saveline(const char *str) {
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
	setprompt ();
	setcurline ();
}

static int up(void *n) {
	R_LOG_DEBUG ("up");
	if (G.n > 0) {
		G.n--;
	}
	setcurline ();
	return 0;
}

static int down(void *n) {
	R_LOG_DEBUG ("down");
	if (G.n < r_list_length (G.lines)) {
		G.n++;
	}
	setcurline ();
	return 0;
}

R_API char *r_cons_editor(RCons *cons, const char *file, const char *str) {
	// bool visual = false; // TODO: should be an argument
	if (I->cb_editor) {
		return I->cb_editor (I->user, file, str);
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
	I->line->hist_up = up;
	I->line->hist_down = down;
	I->line->contents = I->line->buffer.data;
	I->echo = false;
	for (;;) {
		setcurline ();
		const char *line = r_line_readline (cons);
		if (R_STR_ISNOTEMPTY (line)) {
			r_str_trim ((char *)line);
			if (!strcmp (line, ".")) {
				break;
			}
			if (r_str_endswith (line, "\\")) {
				((char *)line)[strlen (line) - 1] = 0;
				saveline (line);
				setcurline ();
				G.n++;
				saveline (NULL);
				setcurline ();
			} else {
				saveline (*line? line: "\\");
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
				emptyline (line);
			}
		}
	}
	if (!r_cons_yesno ('y', "Save? (Y/n)")) {
		r_list_free (G.lines);
		return NULL;
	}
	char *s = r_str_list_join (G.lines, "\n");
	r_str_trim (s);
	I->line->hist_up = NULL;
	I->line->hist_down = NULL;
	I->line->contents = NULL;
	r_list_free (G.lines);
	if (file) {
		r_file_dump (file, (const ut8*)s, -1, 0);
	}
	return s;
}
