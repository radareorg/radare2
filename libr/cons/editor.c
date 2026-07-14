/* radare - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>

struct r_cons_editor_t {
	char prompt[32];
	RList *lines;
	int n; // current line
};

static void setprompt(RCons *cons) {
	RConsEditor *editor = cons->editor;
	snprintf (editor->prompt, sizeof (editor->prompt), "(%d/%d): ", editor->n, r_list_length (editor->lines));
	r_line_set_prompt (cons->line, editor->prompt);
}

static void setcurline(RCons *cons) {
	RConsEditor *editor = cons->editor;
	setprompt (cons);
	const char *nline = r_list_get_n (editor->lines, editor->n);
	const char *curline = r_str_get (nline);
	RLine *line = cons->line;
	r_str_ncpy (line->buffer.data, curline, sizeof (line->buffer.data) - 1);
	line->buffer.data[sizeof (line->buffer.data) - 1] = '\0';
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	line->contents = (char*)curline;
}

static void emptyline(RCons *cons, const char *str) {
	RConsEditor *editor = cons->editor;
	if (editor->n == r_list_length (editor->lines)) {
		// r_list_append (editor->lines, strdup (str));
	} else {
		RListIter *iter = r_list_get_nth (editor->lines, editor->n);
		if (iter) {
			r_list_delete (editor->lines, iter);
		}
	}
	setprompt (cons);
	setcurline (cons);
}

static void saveline(RCons *cons, const char *str) {
	RConsEditor *editor = cons->editor;
	char *s = strdup (str? str: "");
	if (editor->n == r_list_length (editor->lines)) {
		r_list_append (editor->lines, s);
	} else {
		if (str) {
			RListIter *iter = r_list_get_nth (editor->lines, editor->n);
			if (iter) {
				r_list_delete (editor->lines, iter);
			}
			r_list_insert (editor->lines, editor->n, s);
		} else {
			r_list_insert (editor->lines, editor->n, s);
		}
	}
	setprompt (cons);
	setcurline (cons);
}

static int up(RCons *cons, void *n) {
	RConsEditor *editor = cons->editor;
	R_LOG_DEBUG ("up");
	if (editor->n > 0) {
		editor->n--;
	}
	setcurline (cons);
	return 0;
}

static int down(RCons *cons, void *n) {
	RConsEditor *editor = cons->editor;
	R_LOG_DEBUG ("down");
	if (editor->n < r_list_length (editor->lines)) {
		editor->n++;
	}
	setcurline (cons);
	return 0;
}

R_API char *r_cons_editor(RCons *cons, const char *file, const char *str) {
	// bool visual = false; // TODO: should be an argument
	if (cons->cb_editor) {
		return cons->cb_editor (cons->line->user, file, str);
	}
	RConsEditor editor = {0};
	RConsEditor *old_editor = cons->editor;
	cons->editor = &editor;
	editor.lines = r_list_newf (free);
	if (R_STR_ISNOTEMPTY (file)) {
		size_t sz = 0;
		char *data = r_file_slurp (file, &sz);
		r_str_trim (data);
		if (*data) {
			r_list_free (editor.lines);
			editor.lines = r_str_split_list (data, "\n", 0);
		}
		free (data);
		if (!editor.lines) {
			R_LOG_ERROR ("Failed to load '%s'", file);
			cons->editor = old_editor;
			return NULL;
		}
	}
	R_LOG_INFO ("Loaded %d lines. Use ^D or '.' to save and quit", r_list_length (editor.lines));
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
				editor.n++;
				saveline (cons, NULL);
				setcurline (cons);
			} else {
				saveline (cons, *line? line: "\\");
				editor.n++;
			}
		} else {
			if (!line) {
				break;
			}
			if (editor.n == r_list_length (editor.lines)) {
				RListIter *iter;
				int n = 0;
				r_list_foreach (editor.lines, iter, line) {
					eprintf ("%2d| %s\n", n++, line);
				}
			} else {
				emptyline (cons, line);
			}
		}
	}
	if (!r_cons_yesno (cons, 'y', "Save? (Y/n)")) {
		r_list_free (editor.lines);
		cons->editor = old_editor;
		return NULL;
	}
	char *s = r_str_list_join (editor.lines, "\n");
	r_str_trim (s);
	line->hist_up = NULL;
	line->hist_down = NULL;
	line->contents = NULL;
	r_list_free (editor.lines);
	cons->editor = old_editor;
	if (file) {
		r_file_dump (file, (const ut8*)s, -1, 0);
	}
	return s;
}
