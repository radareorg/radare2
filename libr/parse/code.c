/* radare - LGPL - Copyright 2013-2017 - pancake */

#include "r_util.h"
#include "r_types.h"
#include "r_parse.h"
#include "libr_tcc.h"

/* parse C code and return it in key-value form */

static void appendstring(const char *msg, char **s) {
	if (!s) {
		printf ("%s\n", msg);
	} else if (*s) {
		char *p = malloc (strlen (msg) + strlen (*s) + 1);
		if (!p) {
			return;
		}
		strcpy (p, *s);
		free (*s);
		*s = p;
		strcpy (p + strlen (p), msg);
	} else {
		*s = strdup (msg);
	}
}

static int typeload(void *p, const char *k, const char *v) {
	if (!p) {
		return -1;
	}
	int btype = 0;
	RAnal *anal = (RAnal*)p;
	//r_cons_printf ("tk %s=%s\n", k, v);
	// TODO: Add unions support
	if (!strncmp (v, "struct", 6) && strncmp(k, "struct.", 7)) {
		// structure
		btype = VT_STRUCT;
		const char *typename = k;
		int typesize = 0;
		// TODO: Add typesize here
		char* query = sdb_fmt ("struct.%s", k);
		char *members = sdb_get (anal->sdb_types, query, 0);
		char *next, *ptr = members;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				query = sdb_fmt ("struct.%s.%s", k, name);
				char *subtype = sdb_get (anal->sdb_types, query, 0);
				if (!subtype) {
					break;
				}
				char *tmp = strchr (subtype, ',');
				if (tmp) {
					*tmp++ = 0;
					tmp = strchr (tmp, ',');
					if (tmp) {
						*tmp++ = 0;
					}
					char *subname = tmp;
					// TODO: Go recurse here
					query = sdb_fmt ("struct.%s.%s.meta", subtype, subname);
					btype = sdb_num_get (anal->sdb_types, query, 0);
					tcc_sym_push (subtype, 0, btype);
				}
				free (subtype);
				ptr = next;
			} while (next);
			free (members);
		}
		tcc_sym_push ((char *)typename, typesize, btype);
	}
	return 0;
}

R_API char *r_parse_c_file(RAnal *anal, const char *path) {
	char *str = NULL;
	TCCState *T = tcc_new (anal->cpu, anal->bits, anal->os);
	if (!T) {
		return NULL;
	}
	tcc_set_callback (T, &appendstring, &str);
	sdb_foreach (anal->sdb_types, typeload, anal);
	if (tcc_add_file (T, path) == -1) {
		free (str);
		str = NULL;
	}
	tcc_delete (T);
	return str;
}

R_API char *r_parse_c_string(RAnal *anal, const char *code) {
	char *str = NULL;
	TCCState *T = tcc_new (anal->cpu, anal->bits, anal->os);
	if (!T) {
		return NULL;
	}
	tcc_set_callback (T, &appendstring, &str);
	sdb_foreach (anal->sdb_types, typeload, NULL);
	if (tcc_compile_string (T, code) != 0) {
		free (str);
		str = NULL;
	}
	tcc_delete (T);
	return str;
}

R_API int r_parse_is_c_file (const char *file) {
	const char *ext = r_str_lchr (file, '.');
	if (ext) {
		ext = ext + 1;
		if (!strcmp (ext, "cparse")
		||  !strcmp (ext, "c")
		||  !strcmp (ext, "h")) {
			return true;
		}
	}
	return false;
}
