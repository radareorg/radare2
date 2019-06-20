/* radare2 - LGPL - Copyright 2008-2019 - pancake */

#include <r_cons.h>
#include <r_regex.h>
#include <r_util.h>
#include "pager_private.h"

R_API int r_cons_more_str(const char *str, const char *exitkeys) {
	static bool inHelp = false;
	static const char *r_cons_more_help = \
		" space    - page up\n"
		" j        - line down\n"
		" /        - search in buffer\n"
		" _        - enter the hud mode\n"
		" n        - next search result\n"
		" q        - quit\n"
		" ?        - show this help\n"
		"\n";
	int lines_count = 0;
	RRegex *rx = NULL;
	int w, h, ch, to, ui = 1, from = 0, i;
	const char *sreg;
	RList **mla;

	if (!str || !*str) {
		return 0;
	}
	// rcons kills str after flushing the buffer, so we must keep a copy
	char *ostr = strdup (str);
	if (!ostr) {
		return 0;
	}
	char *p = strdup (str);
	if (!p) {
		free (ostr);
		return 0;
	}
	int *lines = pager_splitlines (p, &lines_count);
	if (lines_count < 1) {
		mla = NULL;
	} else {
		mla = calloc (lines_count, sizeof (RList *));
		if (!mla) {
			free (p);
			free (ostr);
			free (lines);
			return 0;
		}
	}
	for (i = 0; i < lines_count; i++) {
		mla[i] = r_list_new ();
	}
	r_cons_set_raw (true);
	r_cons_show_cursor (false);
	r_cons_reset ();
	h = 0;
	while (ui) {
		w = r_cons_get_size (&h);
		to = R_MIN (lines_count, from + h);
		if (from + 3 > lines_count) {
			from = lines_count - 3;
		}
		if (from < 0) {
			from = 0;
		}
		pager_printpage (p, lines, mla, from, to, w);
		ch = r_cons_readchar ();
		if (exitkeys && strchr (exitkeys, ch)) {
			for (i = 0; i < lines_count; i++) {
				r_list_free (mla[i]);
			}
			free (p);
			free (mla);
			free (ostr);
			free (lines);
			return ch;
		}
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case '_':
			r_cons_hud_string (ostr);
			break;
		case '?':
			if (!inHelp) {
				inHelp = true;
				r_cons_more_str (r_cons_more_help, NULL);
				inHelp = false;
			}
			break;
		case ' ': from += h; break;
		case -1: // EOF
		case '\x03': // ^C
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j': from++; break;
		case 'J': from+=h; break;
		case '/': 	/* search */
			r_cons_reset_colors ();
			r_line_set_prompt ("/");
			sreg = r_line_readline ();
			from = R_MIN (lines_count - 1, from);
			/* repeat last search if empty string is provided */
			if (sreg[0]) { /* prepare for a new search */
				if (rx) {
					r_regex_free (rx);
				}
				rx = r_regex_new (sreg, "");
			} else { /* we got an empty string */
				from = pager_next_match (from, mla, lines_count);
				break;
			}
			if (!rx) {
				break;
			}
			/* find all occurrences */
			if (pager_all_matches (p, rx, mla, lines, lines_count)) {
				from = pager_next_match (from, mla, lines_count);
			}
			break;
		case 'n': 	/* next match */
			/* search already performed */
			if (rx) {
				from = pager_next_match (from, mla, lines_count);
			}
			break;
		}
	}
	for (i = 0; i < lines_count; i++) {
		r_list_free (mla[i]);
	}
	free (mla);
	r_regex_free (rx);
	free (lines);
	free (p);
	r_cons_reset_colors ();
	r_cons_set_raw (false);
	r_cons_show_cursor (true);
	free (ostr);
	return 0;
}

R_API void r_cons_more() {
	(void)r_cons_more_str (r_cons_singleton ()->context->buffer, NULL);
}
