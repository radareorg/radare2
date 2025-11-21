/* radare2 - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>

static char *r_cons_message_multiline(RCons *cons, const char *msg) {
	R_RETURN_VAL_IF_FAIL (cons && msg, NULL);
	char *s = strdup (msg);
	RList *lines = r_str_split_list (s, "\n", 0);
	RListIter *iter;
	const char *line;
	int longest = 0;
	r_list_foreach (lines, iter, line) {
		int linelen = strlen (line);
		if (linelen > longest) {
			longest = linelen;
		}
	}
	int rows, cols = r_cons_get_size (cons, &rows);
	char *pad = r_str_pad2 (NULL, 0, ' ', (cols-longest) / 2);
	char *newmsg = r_str_prefix_all (msg, pad);
	free (pad);
	r_cons_clear (cons);
	r_cons_gotoxy (cons, 0, (rows / 2) - (r_list_length (lines) / 2));
	r_cons_println (cons, newmsg);
	r_cons_flush (cons);
	r_cons_gotoxy (cons, 0, rows - 2);
	r_cons_any_key (cons, NULL);
	r_list_free (lines);
	free (s);
	free (newmsg);
	return NULL;
}

R_API char *r_cons_message(RCons *cons, const char *msg) {
	R_RETURN_VAL_IF_FAIL (cons && msg, NULL);
	if (strchr (msg, '\n')) {
		return r_cons_message_multiline (cons, msg);
	}
	int len = strlen (msg);
	int rows, cols = r_cons_get_size (cons, &rows);
	r_cons_clear (cons);
	r_cons_gotoxy (cons, (cols - len) / 2, rows / 2);
	r_cons_println (cons, msg);
	r_cons_flush (cons);
	r_cons_gotoxy (cons, 0, rows - 2);
	r_cons_any_key (cons, NULL);
	return NULL;
}

