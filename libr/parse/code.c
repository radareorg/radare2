/* radare - LGPL - Copyright 2013-2014 - pancake */

#include "r_util.h"
#include "r_types.h"
#include "libr_tcc.h"

/* parse C code and return it in key-value form */

static void appendstring(const char *msg, char **s) {
	if (!s)
		printf ("%s\n", msg);
	else
	if (*s) {
		char *p = malloc (strlen (msg) + strlen (*s)+1);
		strcpy (p, *s);
		free (*s);
		*s = p;
		strcpy (p+strlen (p), msg);
	} else *s = strdup (msg);
}

R_API char *r_parse_c_file(const char *path) {
	char *str = NULL;
	TCCState *T = tcc_new ();
	tcc_set_callback (T, &appendstring, &str);
	if (tcc_add_file (T, path) == -1) {
		free (str);
		str = NULL;
	}
	tcc_delete (T);
	return str;
}

R_API char *r_parse_c_string(const char *code) {
	char *str = NULL;
	TCCState *T = tcc_new ();
	tcc_set_callback (T, &appendstring, &str);
	tcc_compile_string (T, code);
	tcc_delete (T);
	return str;
}

R_API int r_parse_is_c_file (const char *file) {
	const char *ext = r_str_lchr (file, '.');
	if (ext) {
		ext = ext+1;
		if (!strcmp (ext, "cparse")
		||  !strcmp (ext, "c")
		||  !strcmp (ext, "h"))
			return R_TRUE;
	}
	return R_FALSE;
}
