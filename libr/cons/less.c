/* radare2 - LGPL - Copyright 2014 - pancake */

#include <r_cons.h>

static void printpage (const char *line, int *index, int from, int to) {
	int i;
	r_cons_clear00 ();
	for (i=from; i<to; i++) {
// TODO: chop column width, clear lines
		r_cons_printf ("%s\n", line+index[i]);
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

R_API void r_cons_less_str(const char *str) {
	int lines_count;
	int h, ch, to, ui = 1, from = 0;
	char *p = strdup (str);
	int *lines = splitlines (p, &lines_count);
	r_cons_set_raw (R_TRUE);
	r_cons_show_cursor (R_FALSE);
	r_cons_reset ();
	h = 0;
	while (ui) {
		r_cons_get_size (&h);
		to = R_MIN (lines_count, from+h);
		if (from+3>lines_count)
			from = lines_count-3;
		printpage (p, lines, from, to);
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
		}
	}
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
