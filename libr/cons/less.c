/* radare2 - LGPL - Copyright 2014-2025 - pancake */

#include <r_cons.h>
#include <r_regex.h>
#include <r_util.h>
#include "private.h"

static const char *r_cons_less_help = \
	" u/space  - page up/down (same as ^B / ^F)\n"
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
		r_cons_println (cons, str);
		R_LOG_WARN ("Internal less requires scr.interactive=true");
		return 0;
	}

	const bool in_help = str == r_cons_less_help;
	int lines_count = 0;
	RRegex *rx = NULL;
	int w, h, ch, to, ui = 1, from = 0, i;
	int ret = 0;

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
	if (!lines) {
		free (p);
		free (ostr);
		return 0;
	}
	RList **mla = calloc (lines_count, sizeof (RList *));
	if (!mla) {
		free (p);
		free (ostr);
		free (lines);
		return 0;
	}
	for (i = 0; i < lines_count; i++) {
		mla[i] = r_list_newf (free);
	}
	r_cons_set_raw (cons, true);
	r_cons_show_cursor (cons, false);
	r_cons_reset (cons);
	h = 0;
	while (ui) {
		w = r_cons_get_size (cons, &h);
		h = R_MAX (1, h);
		from = R_MAX (0, R_MIN (from, lines_count - 1));
		to = from + R_MIN (h, lines_count - from);
		pager_printpage (cons, p, lines, mla, from, to, w);
		ch = r_cons_readchar (cons);
		if (exitkeys && ch > 0 && strchr (exitkeys, ch)) {
			ret = ch;
			break;
		}
		ch = r_cons_arrow_to_hjkl (cons, ch);
		switch (ch) {
		case '_':
			free (r_cons_hud_string (cons, ostr));
			r_cons_set_raw (cons, true);
			r_cons_show_cursor (cons, false);
			break;
		case '?':
			if (!in_help) {
				(void)r_cons_less_str (cons, r_cons_less_help, NULL);
				r_cons_set_raw (cons, true);
				r_cons_show_cursor (cons, false);
			}
			break;
		case 'h': // ^B
		case 'u':
		case 'K':
			from = R_MAX (0, from - h);
			break;
		case 'l': // ^F
		case ' ':
		case 'J':
			from += R_MIN (h, lines_count - 1 - from);
			break;
		case 'g': from = 0; break;
		case 'G': from = lines_count - h; break;
		case -1: // EOF
		case '\x03': // ^C
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j':
			if (from < lines_count - 1) {
				from++;
			}
			break;
		case 'k':
			if (from > 0) {
				from--;
			}
			break;
		case '/': { /* search */
			char *prompt = r_line_get_prompt (cons->line);
			if (!prompt) {
				break;
			}
			r_cons_reset_colors (cons);
			r_line_set_prompt (cons->line, "/");
			r_cons_show_cursor (cons, true);
			const char *sreg = r_line_readline (cons);
			r_line_set_prompt (cons->line, prompt);
			free (prompt);
			r_cons_set_raw (cons, true);
			r_cons_show_cursor (cons, false);
			if (!sreg) {
				break;
			}
			/* repeat last search if empty string is provided */
			if (sreg[0]) { /* prepare for a new search */
				RRegex *new_rx = r_regex_new (sreg, "");
				if (!new_rx) {
					break;
				}
				r_regex_free (rx);
				rx = new_rx;
			} else { /* we got an empty string */
				from = pager_next_match (from, mla, lines_count);
				break;
			}
			/* find all occurrences */
			if (pager_all_matches (p, rx, mla, lines, lines_count)) {
				from = pager_next_match (from, mla, lines_count);
			}
			break;
		}
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
	r_cons_reset_colors (cons);
	r_cons_set_raw (cons, false);
	r_cons_show_cursor (cons, true);
	free (ostr);
	return ret;
}

R_API void r_cons_less(RCons *cons) {
	(void)r_cons_less_str (cons, cons->context->buffer, NULL);
}
