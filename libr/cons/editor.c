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

static void emptyline(RCons *cons) {
	RConsEditor *editor = cons->editor;
	if (editor->n != r_list_length (editor->lines)) {
		RListIter *iter = r_list_get_nth (editor->lines, editor->n);
		if (iter) {
			r_list_delete (editor->lines, iter);
		}
	}
	setcurline (cons);
}

static bool saveline(RCons *cons, const char *str) {
	RConsEditor *editor = cons->editor;
	char *s = strdup (str? str: "");
	if (!s) {
		return false;
	}
	RListIter *inserted;
	if (editor->n == r_list_length (editor->lines)) {
		inserted = r_list_append (editor->lines, s);
	} else {
		if (str) {
			RListIter *iter = r_list_get_nth (editor->lines, editor->n);
			if (iter) {
				r_list_delete (editor->lines, iter);
			}
			inserted = r_list_insert (editor->lines, editor->n, s);
		} else {
			inserted = r_list_insert (editor->lines, editor->n, s);
		}
	}
	if (!inserted) {
		free (s);
		return false;
	}
	setcurline (cons);
	return true;
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

R_API char *r_cons_editor(RCons *cons, const char *file, const char *str, bool *canceled) {
	if (canceled) {
		*canceled = false;
	}
	R_RETURN_VAL_IF_FAIL (cons && cons->line, NULL);
	// bool visual = false; // TODO: should be an argument
	if (cons->cb_editor) {
		return cons->cb_editor (cons->line->user, file, str);
	}
	RConsEditor editor = { 0 };
	RConsEditor *old_editor = cons->editor;
	RLine *line = cons->line;
	RLineBuffer old_buffer = line->buffer;
	int (*old_hist_up)(RCons *cons, void *user) = line->hist_up;
	int (*old_hist_down)(RCons *cons, void *user) = line->hist_down;
	char *old_contents = line->contents;
	RConsFunctionKey old_cb_fkey = line->cb_fkey;
	int old_echo = cons->echo;
	char *old_prompt = NULL;
	char *result = NULL;
	bool restore_line = false;

	editor.lines = r_list_newf (free);
	if (!editor.lines) {
		goto beach;
	}
	if (R_STR_ISNOTEMPTY (file)) {
		size_t sz = 0;
		char *data = r_file_slurp (file, &sz);
		if (!data) {
			R_LOG_ERROR ("Failed to load '%s'", file);
			goto beach;
		}
		r_str_trim (data);
		if (*data) {
			RList *lines = r_str_split_duplist (data, "\n", false);
			if (!lines) {
				free (data);
				R_LOG_ERROR ("Failed to load '%s'", file);
				goto beach;
			}
			r_list_free (editor.lines);
			editor.lines = lines;
		}
		free (data);
	}
	old_prompt = r_line_get_prompt (line);
	if (!old_prompt) {
		goto beach;
	}
	cons->editor = &editor;
	restore_line = true;
	R_LOG_INFO ("Loaded %d lines. Use ^D or '.' to save and quit", r_list_length (editor.lines));
	line->hist_up = up;
	line->hist_down = down;
	line->contents = line->buffer.data;
	cons->echo = false;
	for (;;) {
		setcurline (cons);
		const char *input = r_line_readline (cons);
		if (!input) {
			break;
		}
		if (R_STR_ISNOTEMPTY (input)) {
			r_str_trim ((char *)input);
			if (!strcmp (input, ".")) {
				break;
			}
			if (r_str_endswith (input, "\\")) {
				((char *)input)[strlen (input) - 1] = 0;
				if (!saveline (cons, input)) {
					goto beach;
				}
				editor.n++;
				if (!saveline (cons, NULL)) {
					goto beach;
				}
			} else {
				if (!saveline (cons, *input? input: "\\")) {
					goto beach;
				}
				editor.n++;
			}
		} else {
			if (editor.n == r_list_length (editor.lines)) {
				RListIter *iter;
				int n = 0;
				const char *list_line;
				r_list_foreach (editor.lines, iter, list_line) {
					eprintf ("%2d| %s\n", n++, list_line);
				}
			} else {
				emptyline (cons);
			}
		}
	}
	if (!r_cons_yesno (cons, 'y', "Save? (Y/n)")) {
		if (canceled) {
			*canceled = true;
		}
		goto beach;
	}
	result = r_str_list_join (editor.lines, "\n");
	if (!result) {
		goto beach;
	}
	r_str_trim (result);
	if (file && !r_file_dump (file, (const ut8 *)result, -1, false)) {
		R_FREE (result);
		goto beach;
	}

beach:
	if (restore_line) {
		r_line_set_prompt (line, old_prompt);
		line->buffer = old_buffer;
		line->hist_up = old_hist_up;
		line->hist_down = old_hist_down;
		line->contents = old_contents;
		line->cb_fkey = old_cb_fkey;
		cons->echo = old_echo;
	}
	cons->editor = old_editor;
	r_list_free (editor.lines);
	free (old_prompt);
	return result;
}
