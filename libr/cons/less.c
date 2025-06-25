/* radare2 - LGPL - Copyright 2014-2025 - pancake */

#include <r_cons.h>
#include <r_regex.h>
#include <r_util.h>
#include "private.h"

static const char *r_cons_less_help = \
	" u/space  - page up/down (same as ^F / ^B)\n"
	" jk       - line down/up\n"
	" gG       - begin/end buffer\n"
	" /        - search in buffer\n"
	" _        - enter the hud mode\n"
	" n/p      - next/prev search result\n"
	" q        - quit\n"
	" ?        - show this help\n"
	"\n";

R_API int r_cons_less_str(RCons * R_NONNULL cons, const char * R_NONNULL str, const char * R_NULLABLE exitkeys) {
	R_RETURN_VAL_IF_FAIL (R_STR_ISNOTEMPTY (str), 0);
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Internal less requires scr.interactive=true");
		return 0;
	}

	bool in_help = false;
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
	r_cons_set_raw (cons, true);
	r_kons_show_cursor (cons, false);
	r_kons_reset (cons);
	h = 0;
	while (ui) {
		w = r_cons_get_size (cons, &h);
		to = R_MIN (lines_count, from + h);
		if (from + 3 > lines_count) {
			from = lines_count - 3;
		}
		if (from < 0) {
			from = 0;
		}
		pager_printpage (cons, p, lines, mla, from, to, w);
		ch = r_cons_readchar (cons);
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
		ch = r_cons_arrow_to_hjkl (cons, ch);
		switch (ch) {
		case '_':
			r_cons_hud_string (cons, ostr);
			break;
		case '?':
			if (!in_help) {
				in_help = true;
				(void)r_cons_less_str (cons, r_cons_less_help, NULL);
				in_help = false;
			}
			break;
		case 104: // ^B
		case 'u':
			from -= h;
			if (from < 0) {
				from = 0;
			}
			break;
		case 108: // ^F
		case ' ': from += h; break;
		case 'g': from = 0; break;
		case 'G': from = lines_count - h; break;
		case -1: // EOF
		case '\x03': // ^C
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j': from++; break;
		case 'J': from += h; break;
		case 'k':
			if (from > 0) {
				from--;
			}
			break;
		case 'K': from = (from >= h)? from - h: 0;
			break;
		case '/': 	/* search */
			r_kons_reset_colors (cons);
			r_line_set_prompt (cons->line, "/");
			sreg = r_line_readline (cons);
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
			r_cons_set_raw (cons, true);
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
	r_kons_reset_colors (cons);
	r_cons_set_raw (cons, false);
	r_kons_show_cursor (cons, true);
	free (ostr);
	return 0;
}

R_API void r_cons_less(RCons *cons) {
	(void)r_cons_less_str (cons, cons->context->buffer, NULL);
}
