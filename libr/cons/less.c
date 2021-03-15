/* radare2 - LGPL - Copyright 2014-2019 - pancake, Judge_Dredd */

#include <r_cons.h>
#include <r_regex.h>
#include <r_util.h>
#include "pager_private.h"

R_API int r_cons_less_str(const char *str, const char *exitkeys) {
	r_return_val_if_fail (str && *str, 0);
	if (!r_cons_is_interactive ()) {
		eprintf ("Internal less requires scr.interactive=true.\n");
		return 0;
	}

	static int in_help = false;
	static const char *r_cons_less_help = \
		" u/space  - page up/down\n"
		" jk       - line down/up\n"
		" gG       - begin/end buffer\n"
		" /        - search in buffer\n"
		" _        - enter the hud mode\n"
		" n/p      - next/prev search result\n"
		" q        - quit\n"
		" ?        - show this help\n"
		"\n";
	int lines_count = 0;
	RRegex *rx = NULL;
	int w, h, ch, to, ui = 1, from = 0, i;
	const char *sreg;
	RList **mla;

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
			if (!in_help) {
				in_help = true;
				(void)r_cons_less_str (r_cons_less_help, NULL);
				in_help = false;
			}
			break;
		case 'u':
			from -= h;
			if (from < 0) {
				from = 0;
			}
			break;
		case ' ': from += h; break;
		case 'g': from = 0; break;
		case 'G': from = lines_count-h; break;
		case -1: // EOF
		case '\x03': // ^C
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j': from++; break;
		case 'J': from+=h; break;
		case 'k':
			if (from > 0) {
				from--;
			}
			break;
		case 'K': from = (from>=h)? from-h: 0;
			break;
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
		case 'N':
		case 'p': 	/* previous match */
			if (rx) {
				from = pager_prev_match (from, mla);
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

R_API void r_cons_less(void) {
	(void)r_cons_less_str (r_cons_singleton ()->context->buffer, NULL);
}

#if 0
main (int argc, char **argv) {
	char *s = r_file_slurp (argv[1], NULL);
	r_cons_new ();
	r_cons_less (s);
}
#endif
