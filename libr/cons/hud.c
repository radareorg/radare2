/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_cons.h>
#include <ctype.h>

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
		if (!ret)
			ret = strdup ("");
		return ret;
	}
	return NULL;
}

R_API char *r_cons_hud_string(const char *s) {
	int i;
	char *os, *ret, *o = strdup (s);
	RList *fl = r_list_new ();
	if (!fl) {
		free (o);
		return NULL;
	}
	fl->free = free;
	for (os=o, i=0; o[i]; i++) {
		if (o[i]=='\n') {
			o[i] = 0;
			if (*os && *os != '#')
				r_list_append (fl, strdup (os));
			os = o + i + 1;
		}
	}
	ret = r_cons_hud (fl, NULL);
	free (o);
	r_list_free (fl);
	return ret;
}

static char *strmatch (char *pos, char *buf) {
	char *p, *os = buf;
	for (p = buf; *p; p++) {
		if (*p==' ') {
			*p = 0;
			if (!r_str_casestr (pos, os)) {
//r_cons_printf ("FAIL ((%s), %s)\n", pos, os);
				*p = ' ';
				return NULL;
			}
//r_cons_printf ("CHK (%s)\n", os);
			*p = ' ';
			os = p+1;
		}
	}
	return (char *)r_str_casestr (pos, os);
}

R_API char *r_cons_hud(RList *list, const char *prompt) {
	int ch, nch, first, n, j, i = 0;
	int choose = 0;
	char *p, buf[128];
	RListIter *iter;
	char *match = NULL;
	void *pos;
	buf[0] = 0;
	r_cons_clear ();
	for (;;) {
		first = 1;
		r_cons_gotoxy (0, 0);
		n = 0;
		match = NULL;
		if (prompt && *prompt)
			r_cons_printf (">> %s\n", prompt);
		r_cons_printf ("> %s|\n", buf);
		r_list_foreach (list, iter, pos) {
			if (!buf[0] || strmatch (pos, buf)) {
				char *x = strchr (pos, '\t');
				// remove \t.*
				if (!choose || n>=choose) {
					if (x) *x = 0;
					p = strdup (pos);
					for (j=0; p[j]; j++) {
						if (strchr (buf, p[j]))
							p[j] = toupper ((unsigned char)p[j]);
					}
					r_cons_printf (" %c %s\n", first?'-':' ', p);
					free (p);
					if (x) *x = '\t';
					if (first) match = pos;
					first = 0;
				}
				n++;
			}
		}
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		nch = r_cons_arrow_to_hjkl (ch);
		if (nch == 'j' && ch != 'j') {
			if (choose+1 < n)
				choose++;
		} else if (nch == 'k' && ch != 'k') {
			if (choose>=0)
				choose--;
		} else
		switch (ch) {
		case 9: // \t
			if (choose+1 < n)
				choose++;
			else choose = 0;
			break;
		case 10: // \n
		case 13: // \r
			choose = 0;
	//		if (!*buf)
	//			return NULL;
			if (n >= 1) {
				//eprintf ("%s\n", buf);
				//i = buf[0] = 0;
				return strdup (match);
			} // no match!
			break;
		case 23: // ^w
			choose = 0;
			i = buf[0] = 0;
			break;
		case 0x1b: // ESC
			return NULL;
		case 8: // bs
		case 127: // bs
			choose = 0;
			if (i<1) return NULL;
			buf[--i] = 0;
			break;
		default:
			if (IS_PRINTABLE (ch)) {
				choose = 0;
				buf[i++] = ch;
				buf[i] = 0;
			}
			break;
		}
	}
	return NULL;
}

R_API char *r_cons_hud_path(const char *path, int dir) {
	char *tmp = NULL, *ret = NULL;
	RList *files;
	if (path){
		while (*path==' ')
			path++;
		tmp = (*path)? strdup(path): strdup ("./");
	} else
		tmp = strdup ("./");

	files = r_sys_dir (tmp);
	if (files) {
		ret = r_cons_hud (files, tmp);
		if (ret) {
			tmp = r_str_concat (tmp, "/");
			tmp = r_str_concat (tmp, ret);
			ret = r_file_abspath (tmp);
			free (tmp);
			tmp = ret;
			if (r_file_is_directory (tmp)) {
				ret = r_cons_hud_path (tmp, dir);
				free (tmp);
				tmp = ret;
			}
		}
		r_list_free (files);
	} else eprintf ("No files found\n");
	if (!ret) {
		free (tmp);
		return NULL;
	}
	return tmp;
}

// TODO: Add fmt support
R_API char *r_cons_message(const char *msg) {
	int cols, rows;
	int len = strlen (msg);
	cols = r_cons_get_size (&rows);

	r_cons_clear ();
	r_cons_gotoxy ((cols-len)/2, rows/2); // XXX
	/// TODO: add square, or talking clip here
	r_cons_printf ("%s\n", msg);
	r_cons_flush ();
	r_cons_gotoxy (0, rows-2); // XXX
	r_cons_any_key ();
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
	res = r_cons_hud (fl, NULL);
	r_cons_clear ();
	if (res) {
		r_cons_printf ("%s\n", res);
		free (res);
	}
	r_cons_flush ();
	r_cons_free ();
}
#endif
