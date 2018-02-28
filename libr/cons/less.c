/* radare2 - LGPL - Copyright 2014-2018 - pancake, Judge_Dredd */

#include <r_cons.h>
#include <r_regex.h>
#include <r_util.h>

static void color_line(const char *line, RStrpool *p, RList *ml){
	int m_len, offset = 0;
	char *m_addr;
	RListIter *it;
	RRegexMatch *m;
	char *inv[2] = {
		R_CONS_INVERT (true, true),
		R_CONS_INVERT (false, true)
	};
	int linv[2] = {
		strlen (inv[0]),
		strlen (inv[1])
	};
	r_strpool_empty (p);
	r_list_foreach (ml, it, m) {
		/* highlight a match */
		r_strpool_memcat (p, line + offset, m->rm_so - offset);
		r_strpool_memcat (p, inv[0], linv[0]);
		m_len = m->rm_eo - m->rm_so;
		if (m_len < 0) {
			m_len = 0;
		}
		m_addr = r_str_ndup (line + m->rm_so, m_len);
		if (m_addr) {
			/* in case there's a CSI in the middle of this match*/
			m_len = r_str_ansi_filter (m_addr, NULL, NULL, m_len);
			if (m_len<0) m_len = 0;
			r_strpool_memcat (p, m_addr, m_len);
			r_strpool_memcat (p, inv[1], linv[1]);
			offset = m->rm_eo;
			free(m_addr);
		}

	}
	/* append final part of string w/o matches */
	r_strpool_append (p, line + offset);
}

static void printpage (const char *line, int *index, RList **mla, int from, int to, int w) {
	int i;

	r_cons_clear00 ();
	if (from < 0 || to < 0) {
		return;
	}

	RStrpool *p = r_strpool_new (0);
	if (!p) {
		return;
	}
	for (i = from; i < to; i++) {
		color_line (line + index[i], p, mla[i]);
		r_strpool_ansi_chop (p, w);
		r_cons_reset_colors ();
		r_cons_println (p->str);
	}
	r_strpool_free(p);
	r_cons_flush ();
}

static int *splitlines (char *s, int *lines_count) {
	int lines_size = 128;
	int *lines = NULL;
	int i, row = 0;
	int sidx = 0;

	if (lines_size * sizeof (int) < lines_size) {
		return NULL;
	}
	lines = malloc (lines_size * sizeof (int));
	if (!lines) {
		return NULL;
	}
	lines[row++] = 0;
	for (i = 0; s[i]; i++) {
		if (row >= lines_size) {
			int *tmp;
			lines_size += 128;
			if (lines_size * sizeof(int) < lines_size) {
				free (lines);
				return NULL;
			}
			tmp = realloc (lines, lines_size * sizeof(int));
			if (!tmp) {
				free (lines);
				return NULL;
			}
			lines = tmp;
		}
		if (s[i] == '\n') {
			s[i] = 0;
			lines[row++] = i + 1;
		}
		sidx++;
	}
	*lines_count = row;
	return lines;
}

static int next_match(int from, RList **mla, int lcount){
	int l;
	if (from > lcount - 2) {
		return from;
	}
	for (l = from + 1; l < lcount; l++){
		/* if there's at least one match on the line */
		if (r_list_first(mla[l])) {
			return l;
		}
	}
	return from;
}

static int prev_match(int from, RList **mla){
	int l;
	if (from < 1) {
		return from;
	}
	for (l = from - 1; l > 0; l--) {
		if (r_list_first(mla[l])) {
			return l;
		}
	}
	return from;
}

static int all_matches(const char *s, RRegex *rx, RList **mla, int *lines, int lcount) {
	int l, f = false;
	RRegexMatch m;
	int slen;
	for (l = 0; l < lcount; l++) {
		m.rm_so = 0;
		const char *loff = s + lines[l]; /* current line offset */
		char *clean = strdup (loff);
		if (!clean) return 0;
		int *cpos = NULL;
		int ncpos = r_str_ansi_filter (clean, NULL, &cpos, 0);
		m.rm_eo = slen = strlen (clean);
		r_list_purge (mla[l]);
		while (!r_regex_exec (rx, clean, 1, &m, R_REGEX_STARTEND)) {
			RRegexMatch *ms = R_NEW0 (RRegexMatch);
			if (!cpos || m.rm_so >= ncpos) {
				break;
			}
			ms->rm_so = cpos[m.rm_so];
			ms->rm_eo = cpos[m.rm_eo];
			r_list_append (mla[l], ms);
			m.rm_so = m.rm_eo;
			m.rm_eo = slen;
			f = true;
		}
		free (cpos);
		free (clean);
	}
	return f;
}

R_API int r_cons_less_str(const char *str, const char *exitkeys) {
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
	int *lines = splitlines (p, &lines_count);
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
	w = h = 0;
	while (ui) {
		w = r_cons_get_size (&h);
		to = R_MIN (lines_count, from + h - 1);
		if (from + 3 > lines_count) {
			from = lines_count - 3;
		}
		if (from < 0) {
			from = 0;
		}
		printpage (p, lines, mla, from, to, w);
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
				r_cons_less_str (r_cons_less_help, NULL);
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
		case 'G': from = lines_count-1-h; break;
		case -1: // EOF
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j': from++; break;
		case 'J': from+=h; break;
		case 'k': if (from>0) from--; break;
		case 'K': from = (from>=h)? from-h: 0;
			break;
		case '/': 	/* search */
			r_cons_reset_colors ();
			r_line_set_prompt ("/");
			sreg = r_line_readline ();
			from = R_MIN(lines_count - 1, from);
			/* repeat last search if empty string is provided */
			if (sreg[0]) { /* prepare for a new search */
				if (rx) r_regex_free(rx);
				rx = r_regex_new(sreg, "");
			} else { /* we got an empty string */
				from = next_match(from, mla, lines_count);
				break;
			}
			if (!rx) break;
			/* find all occurences */
			if (all_matches (p, rx, mla, lines, lines_count))
				from = next_match(from, mla, lines_count);
			break;
		case 'n': 	/* next match */
			/* search already performed */
			if (rx) {
				from = next_match (from, mla, lines_count);
			}
			break;
		case 'p': 	/* previous match */
			if (rx) {
				from = prev_match(from, mla);
			}
			break;
		}
	}
	for (i = 0; i < lines_count; i++) {
		r_list_free (mla[i]);
	}
	free (mla);
	if (rx) r_regex_free (rx);
	free (lines);
	free (p);
	r_cons_reset_colors ();
	r_cons_set_raw (false);
	r_cons_show_cursor (true);
	free (ostr);
	return 0;
}

R_API void r_cons_less() {
	r_cons_less_str (r_cons_singleton ()->buffer, NULL);
}

#if 0
main (int argc, char **argv) {
	char *s = r_file_slurp (argv[1], NULL);
	r_cons_new ();
	r_cons_less (s);
}
#endif
