/* radare2 - LGPL - Copyright 2014-2015 - pancake, Judge_Dredd */

#include <r_cons.h>
#include <r_regex.h>		/* less / regex search */
#include <r_util.h>
#define NMATCHES 10		/* max number of matches per line */

static void color_line(const char *line, RStrpool *p, RRegexMatch *ms){

	int i;
	int offset = 0;

	char *inv[2] = {R_CONS_INVERT(R_TRUE, R_TRUE),
			R_CONS_INVERT(R_FALSE, R_TRUE)};
	int linv[2] = {strlen(inv[0]), strlen(inv[1])};

	r_strpool_empty(p);
	for (i = 0; i < NMATCHES; i++){
		if (ms[i].rm_eo && (i < NMATCHES - 1)) {
			/* highlight a match */
			r_strpool_memcat (p, line + offset,
					  ms[i].rm_so - offset);
			r_strpool_memcat (p, inv[0], linv[0]);

			int m_len = ms[i].rm_eo - ms[i].rm_so;
			char *m_addr = strndup(line + ms[i].rm_so, m_len);
			if(r_str_ansi_chrn(m_addr, m_len) - m_addr < m_len ){
				/* there's a CSI in the middle of
				 * this match*/
				m_len = r_str_ansi_filter(m_addr,
							  NULL, NULL, m_len);
			}
			r_strpool_memcat (p, m_addr, m_len);
			r_strpool_memcat (p, inv[1], linv[1]);

			offset = ms[i].rm_eo;

			free(m_addr);
		} else {
			/* append final part of string w/o matches */
			r_strpool_append(p, line + offset);
			break;
		}
	}

}

static void printpage (const char *line, int *index, RRegexMatch **ms,
		       int from, int to, int w) {
	int i;
	RStrpool *p;

	r_cons_clear00 ();
	if (from <0 || to <0) {
		return;
	}
	p = r_strpool_new(0);
	for (i=from; i<to; i++) {
		color_line(line + index[i], p, ms[i]);
		r_strpool_ansi_chop(p, w);
		r_cons_reset_colors();
		r_cons_printf ("%s\n", p->str);
	}
	r_strpool_free(p);
	r_cons_flush ();
}

static int *splitlines (char *s, int *lines_count) {
	int lines_size = 128;
	int *lines = malloc (lines_size*sizeof(int));
	int i, row = 0;
	int sidx = 0;
	lines[row++] = 0;
	for (i=0; s[i]; i++) {
		if (row>=lines_size) {
			lines_size += 128;
			lines = realloc (lines, lines_size*sizeof(int));
		}
		if (s[i]=='\n') {
			s[i] = 0;
			lines[row++] = i+1;
		}
		sidx++;
	}
	*lines_count = row;
	return lines;
}

static int next_match(int from, RRegexMatch **ms, int lcount){
	int l;
	if(from > lcount - 2) return from;
	for(l = from + 1; l < lcount; l++){
		/* if there's at least one match on the line */
		if(ms[l][0].rm_eo) return l;
	}
	return from;
}

static int prev_match(int from, RRegexMatch **ms){
	int l;
	if(from < 1) return from;
	for(l = from - 1; l > 0; l--){
		if(ms[l][0].rm_eo) return l;
	}
	return from;
}

static int all_matches(const char *s, RRegex *rx, RRegexMatch **ms,
		       int *lines, int lcount){
	int num, l, fnd, f = R_FALSE;
	RRegexMatch m;
	int slen;
	for(l = 0; l < lcount; l++){
		num = 0;
		m.rm_so = 0;
		const char *loff = s + lines[l]; /* current line offset */
		char *clean = strdup(loff);
		int *cpos;
		r_str_ansi_filter(clean, NULL, &cpos, 0);
		m.rm_eo = slen = strlen(clean);
		memset(ms[l], 0, NMATCHES * sizeof(RRegexMatch));
		while(num < NMATCHES){
			fnd = r_regex_exec(rx, clean, 1, &m, R_REGEX_STARTEND);
			if(!fnd) {
				ms[l][num].rm_so = cpos[m.rm_so];
				ms[l][num].rm_eo = cpos[m.rm_eo];
				m.rm_so = m.rm_eo;
				m.rm_eo = slen;
				f = R_TRUE;
				num++;
			} else break; /* no more on this line */
		}
		free(cpos);
		free(clean);
	}
	return f;
}

R_API void r_cons_less_str(const char *str) {
	int lines_count;
	RRegex *rx = NULL;
	int w, h, ch, to, ui = 1, from = 0, i;
	const char *sreg;

	if(str == NULL || str[0] == '\0') return;
	char *p = strdup (str);
	int *lines = splitlines (p, &lines_count);

	RRegexMatch **ms = malloc(lines_count * sizeof(void *));
	for(i = 0; i < lines_count; i++)
		ms[i] = calloc(NMATCHES, sizeof(RRegexMatch));

	r_cons_set_raw (R_TRUE);
	r_cons_show_cursor (R_FALSE);
	r_cons_reset ();
	w = h = 0;
	while (ui) {
		w = r_cons_get_size (&h);
		to = R_MIN (lines_count, from+h);
		if (from+3>lines_count)
			from = lines_count-3;
		if (from<0) from = 0;
		printpage (p, lines, ms, from, to, w);
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
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
			r_cons_reset_colors();
			r_line_set_prompt("/");
			sreg = r_line_readline();
			from = R_MIN(lines_count - 1, from);
			/* repeat last search if empty string is provided */
			if(sreg[0]){ /* prepare for a new search */
				if(rx) r_regex_free(rx);
				rx = r_regex_new(sreg, "");
			} else { /* we got an empty string */
				from = next_match(from, ms, lines_count);
				break;
			}
			if(!rx) break;
			/* find all occurences */
			if(all_matches(p, rx, ms, lines, lines_count))
				from = next_match(from, ms, lines_count);
			break;
		case 'n': 	/* next match */
			/* search already performed */
			if(rx) from = next_match(from, ms, lines_count);
			break;
		case 'p': 	/* previous match */
			if(rx) from = prev_match(from, ms);
			break;
		}
	}
	for(i = 0; i < lines_count; i++) free(ms[i]);
	free(ms);
	if(rx) r_regex_free(rx);
	free (lines);
	free (p);
	r_cons_reset_colors();
	r_cons_set_raw (R_FALSE);
	r_cons_show_cursor (R_TRUE);
}

R_API void r_cons_less() {
	r_cons_less_str (r_cons_singleton ()->buffer);
}

#if 0
main (int argc, char **argv) {
	char *s = r_file_slurp (argv[1], NULL);
	r_cons_new ();
	r_cons_less (s);
}
#endif
