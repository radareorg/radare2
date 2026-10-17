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
	r_str_ncpy (line->state.buffer.data, curline, sizeof (line->state.buffer.data));
	line->state.buffer.index = line->state.buffer.length = strlen (line->state.buffer.data);
	line->state.contents = (char*)curline;
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
	bool saved;
	if (editor->n == r_list_length (editor->lines)) {
		saved = r_list_append (editor->lines, s);
	} else if (str) {
		saved = r_list_set_n (editor->lines, editor->n, s);
	} else {
		saved = r_list_insert (editor->lines, editor->n, s);
	}
	if (!saved) {
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
		if ((editor->n < r_list_length (editor->lines) || cons->line->state.buffer.length > 0)
				&& !saveline (cons, cons->line->state.buffer.data)) {
			return 0;
		}
		editor->n--;
		setcurline (cons);
	}
	return 0;
}

static int down(RCons *cons, void *n) {
	RConsEditor *editor = cons->editor;
	R_LOG_DEBUG ("down");
	if (editor->n < r_list_length (editor->lines) || cons->line->state.buffer.length > 0) {
		if (!saveline (cons, cons->line->state.buffer.data)) {
			return 0;
		}
		editor->n++;
		setcurline (cons);
	}
	return 0;
}

R_API char *r_cons_editor(RCons *cons, const char *file, const char *str, bool *canceled) {
	if (canceled) {
		*canceled = false;
	}
	R_RETURN_VAL_IF_FAIL (cons && cons->line, NULL);
	// bool visual = false; // TODO: should be an argument
	if (cons->cb_editor) {
		return cons->cb_editor (cons->line->user, file, str, canceled);
	}
	RConsEditor editor = { 0 };
	RConsEditor *old_editor = cons->editor;
	RLine *line = cons->line;
	RLineState old_state = line->state;
	line->state.prompt = NULL;
	bool old_echo = cons->echo;
	const bool edit_file = R_STR_ISNOTEMPTY (file);
	char *result = NULL;

	editor.lines = r_list_newf (free);
	if (!editor.lines) {
		goto beach;
	}
	if (str || edit_file) {
		char *data = str? strdup (str): r_file_slurp (file, NULL);
		if (!data) {
			R_LOG_ERROR ("Failed to load editor contents");
			goto beach;
		}
		if (*data) {
			RList *lines = r_str_split_duplist (data, "\n", false);
			if (!lines) {
				free (data);
				R_LOG_ERROR ("Failed to load editor contents");
				goto beach;
			}
			r_list_free (editor.lines);
			editor.lines = lines;
		}
		free (data);
	}
	RListIter *iter;
	const char *text;
	int line_number = 1;
	r_list_foreach (editor.lines, iter, text) {
		if (strlen (text) >= sizeof (line->state.buffer.data)) {
			R_LOG_ERROR ("Line %d exceeds the editor limit of %d bytes", line_number, R_LINE_BUFSIZE - 1);
			goto beach;
		}
		line_number++;
	}
	cons->editor = &editor;
	R_LOG_INFO ("Loaded %d lines. Use ^D or '.' to save and quit", r_list_length (editor.lines));
	line->state.hist_up = up;
	line->state.hist_down = down;
	line->state.contents = line->state.buffer.data;
	cons->echo = false;
	for (;;) {
		setcurline (cons);
		const char *input = r_line_readline (cons);
		if (!input) {
			break;
		}
		if (R_STR_ISNOTEMPTY (input)) {
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
				if (!saveline (cons, input)) {
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
	if (edit_file && !r_file_dump (file, (const ut8 *)result, -1, false)) {
		R_FREE (result);
		goto beach;
	}

beach:
	free (line->state.prompt);
	line->state = old_state;
	cons->echo = old_echo;
	cons->editor = old_editor;
	r_list_free (editor.lines);
	return result;
}
