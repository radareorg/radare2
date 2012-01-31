/* radare - LGPL - Copyright 2008-2012 pancake<nopcode.org> */
#include <r_cons.h>

#if 0
TODO?
 - initial value
 - default value (if null, use this)
 - list of items filtered by user input
 - execute command with info from row (display disasm or hexdump from off)
 - we need a more complex data structure CSV?
   - string, key, command
 - commands can be passed to the hud callback
 - commands: menu...
#endif

R_API char *r_cons_hud_file(const char *f) {
	char *s = r_file_slurp (f, NULL);
	if (s) {
		char *ret = r_cons_hud_string (s);
		free (s);
		return ret;
	}
	return NULL;
}

R_API char *r_cons_hud_string(const char *s) {
	int i;
	char *ret, *o = strdup (s);
	//RFList fl = r_flist_new (10);
	RList *fl = r_list_new ();
	fl->free = free;
	char *os = o;
	for (i=0; o[i]; i++) {
		if (o[i]=='\n') {
			o[i] = 0;
			if (!fl) {
				// XXX memleak
				return NULL;
			}
			if (*os)
			r_list_append (fl, strdup (os));
			os = o+i+1;
		}
	}
	ret = r_cons_hud (fl);
	r_list_free (fl);
	return ret;
}

static char *strmatch (char *pos, char *buf) {
	int spaces = 0;
	char *p, *os = buf;
	for (p = buf; *p; p++) {
		if (*p==' ') {
			spaces = 1;
			*p = 0;
			if (!strcasestr (pos, os)) {
//r_cons_printf ("FAIL ((%s), %s)\n", pos, os);
				*p = ' ';
				return NULL;
			}
//r_cons_printf ("CHK (%s)\n", os);
			*p = ' ';
			os = p+1;
		}
	}
	return strcasestr (pos, os);
}

R_API char *r_cons_hud(RList *list) {
	int n, i = 0;
	int ch, nch;
	char buf[128];
	RListIter *iter;
	char *match = NULL;
	void *pos;
	buf[0] = 0;
	r_cons_clear ();
	for (;;) {
		r_cons_gotoxy (0, 0);
		n = 0;
		match = NULL;
		r_cons_printf ("> %s|\n", buf);
		r_list_foreach (list, iter, pos) {
			if (!buf[0] || strmatch (pos, buf)) {
				char *x = strchr (pos, '\t');
				if (x) *x = 0;
				// remove \t.*
				r_cons_printf (" - %s\n", pos);
				if (x) *x = '\t';
				if (n==0) match = pos;
				n++;
			}
		}
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		nch = r_cons_arrow_to_hjkl (ch);
//eprintf ("%d %d\n", ch, nch); sleep (1);
		switch (ch) {
		case 10: // \n
		case 13: // \r
			if (!*buf)
				return NULL;
			if (n == 1) {
				//eprintf ("%s\n", buf);
				//i = buf[0] = 0;
				return strdup (match);
			} // no match!
			break;
		case 23: // ^w
			i = buf[0] = 0;
			break;
		case 27: // ignore
			break;
		case 127: // bs
			if (i<1) return NULL;
			buf[--i] = 0;
			break;
		default:
			buf[i++] = ch;
			buf[i] = 0;
			break;
		}
	}
	return NULL;
}

#ifdef MAIN
main() {
	char *res;
	RFList fl = r_flist_new (3);
	r_flist_set (fl, 0, "foo is pure cow");
	r_flist_set (fl, 1, "bla is kinda crazy");
	r_flist_set (fl, 2, "funny to see you here");
	
	r_cons_new ();
	res = r_cons_hud (fl);
	r_cons_clear ();
	if (res) {
		r_cons_printf ("%s\n", res);
		free (res);
	}
	r_cons_flush ();
	r_cons_free ();
}
#endif
