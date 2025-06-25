/* radare2 - LGPL - Copyright 2019-2025 - pancake */

#include <r_regex.h>
#include <r_util.h>
#include <r_cons.h>
#include "private.h"

R_IPI void pager_color_line(RCons *cons, const char *line, RStrpool *p, RList *ml) {
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
			if (m_len < 0) {
				m_len = 0;
			}
			r_strpool_memcat (p, m_addr, m_len);
			r_strpool_memcat (p, inv[1], linv[1]);
			offset = m->rm_eo;
			free (m_addr);
		}

	}
	/* append final part of string w/o matches */
	r_strpool_append (p, line + offset);
}

R_IPI void pager_printpage(RCons *cons, const char *line, int *index, RList **mla, int from, int to, int w) {
	int i;

	r_kons_clear00 (cons);
	if (from < 0 || to < 0) {
		return;
	}

	RStrpool *p = r_strpool_new ();
	if (!p) {
		return;
	}
	for (i = from; i < to; i++) {
		pager_color_line (cons, line + index[i], p, mla[i]);
		r_strpool_ansi_trim (p, w);
		r_kons_reset_colors (cons);
		if (i + 1 == to) {
			r_kons_print (cons, p->str);
		} else {
			r_kons_println (cons, p->str);
		}
	}
	r_strpool_free (p);
	r_kons_flush (cons);
}

R_IPI int pager_next_match(int from, RList **mla, int lcount) {
	int l;
	if (from > lcount - 2) {
		return from;
	}
	for (l = from + 1; l < lcount; l++) {
		/* if there's at least one match on the line */
		if (r_list_first (mla[l])) {
			return l;
		}
	}
	return from;
}

R_IPI int pager_prev_match(int from, RList **mla) {
	int l;
	if (from < 1) {
		return from;
	}
	for (l = from - 1; l > 0; l--) {
		if (r_list_first (mla[l])) {
			return l;
		}
	}
	return from;
}

R_IPI bool pager_all_matches(const char *s, RRegex *rx, RList **mla, int *lines, int lcount) {
	bool res = false;
	RRegexMatch m = {0};
	int l, slen;
	for (l = 0; l < lcount; l++) {
		m.rm_so = 0;
		const char *loff = s + lines[l]; /* current line offset */
		char *clean = strdup (loff);
		if (!clean) {
			return false;
		}
		int *cpos = NULL;
		int ncpos = r_str_ansi_filter (clean, NULL, &cpos, -1);
		m.rm_eo = slen = strlen (clean);
		r_list_purge (mla[l]);
		while (!r_regex_exec (rx, clean, 1, &m, R_REGEX_STARTEND)) {
			if (!cpos || m.rm_so >= ncpos) {
				break;
			}
			if (cpos) {
				RRegexMatch *ms = R_NEW0 (RRegexMatch);
				ms->rm_so = cpos[m.rm_so];
				ms->rm_eo = cpos[m.rm_eo];
				r_list_append (mla[l], ms);
			}
			m.rm_so = m.rm_eo;
			m.rm_eo = slen;
			res = true;
		}
		free (cpos);
		free (clean);
	}
	return res;
}

R_IPI int *pager_splitlines(char *s, int *lines_count) {
	int lines_size = 128;
	int i, row = 0;

	if (lines_size * sizeof (int) < lines_size) {
		return NULL;
	}
	int *lines = (int *)malloc (lines_size * sizeof (int));
	if (lines) {
		lines[row++] = 0;
		for (i = 0; s[i]; i++) {
			if (row >= lines_size) {
				int *tmp;
				lines_size += 128;
				if (lines_size * sizeof (int) < lines_size) {
					free (lines);
					return NULL;
				}
				tmp = realloc (lines, lines_size * sizeof (int));
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
		}
		*lines_count = row;
	}
	return lines;
}
