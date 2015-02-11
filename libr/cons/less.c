/* radare2 - LGPL - Copyright 2014 - pancake */

#include <r_cons.h>
#include <r_regex.h>		/* less / regex search */

static void printpage (const char *line, int *index,
		       RRegexMatch *ms, int from, int to) {
	int i;
	const char *laddr;
	r_cons_clear00 ();
	for (i=from; i<to; i++) {
// TODO: chop column width, clear lines
		laddr = line + index[i];
		if(!ms[i].rm_eo) r_cons_printf ("%s\n", laddr);
		else {		/* highlight a match */
			r_cons_memcat(laddr, ms[i].rm_so);
			r_cons_invert(R_TRUE, R_TRUE);
			r_cons_memcat(laddr + ms[i].rm_so,
				      ms[i].rm_eo - ms[i].rm_so);
			r_cons_invert(R_FALSE, R_TRUE);
			r_cons_printf ("%s\n", laddr + ms[i].rm_eo);
		}
	}
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

static int next_match(int from, RRegexMatch *ms, int lcount){
	int l;
	if(from > lcount - 2) return from;
	for(l = from + 1; l < lcount; l++){
		if(ms[l].rm_eo) return l;
	}
	return from;
}

static int prev_match(int from, RRegexMatch *ms){
	int l;
	if(from < 1) return from;
	for(l = from - 1; l > 0; l--){
		if(ms[l].rm_eo) return l;
	}
	return from;
}

/* find all matches, ms[i] will contain match offsets relative to start
 * of string number i! */
static int all_matches(const char *s, RRegex *rx, RRegexMatch *ms,
		       int *lines, int lcount){
	int l, fnd, f = R_FALSE;
	RRegexMatch m;
	for(l = 0; l < lcount; l++){
		fnd = r_regex_exec(rx, s + lines[l], 1, &m, 0);
		if(!fnd){
			ms[l] = m;
			f = R_TRUE;
		}
	}
	return f;
}

R_API void r_cons_less_str(const char *str) {
	int lines_count;
	RRegex *rx = NULL;
	int h, ch, to, ui = 1, from = 0;
	const char *sreg;
	char *p = strdup (str);
	int *lines = splitlines (p, &lines_count);
	RRegexMatch *ms = calloc(lines_count, sizeof(RRegexMatch));
	r_cons_set_raw (R_TRUE);
	r_cons_show_cursor (R_FALSE);
	r_cons_reset ();
	h = 0;
	while (ui) {
		r_cons_get_size (&h);
		to = R_MIN (lines_count, from+h);
		if (from+3>lines_count)
			from = lines_count-3;
		printpage (p, lines, ms, from, to);
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case ' ': from += h; break;
		case 'g': from = 0; break;
		case 'G': from = lines_count-1-h; break;
		case 'q': ui = 0; break;
		case '\r':
		case '\n':
		case 'j': from++; break;
		case 'J': from+=h; break;
		case 'k': if (from>0) from--; break;
		case 'K': from = (from>=h)? from-h: 0;
			break;
		case '/': 	/* search */
			r_line_set_prompt("/");
			sreg = r_line_readline();
			from = R_MIN(lines_count - 1, from);
			/* repeat last search if empty string is provided */
			if(sreg[0]){ /* prepare for a new search */
				if(rx) r_regex_free(rx);
				rx = r_regex_new(sreg, "");
				memset (ms, 0, lines_count*sizeof(RRegexMatch));
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
	if(rx) r_regex_free(rx);
	free (lines);
	free (p);
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
