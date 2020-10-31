/* radare - LGPL - Copyright 2013-2019 - pancake */

#include "r_util.h"
#include "r_types.h"
#include "r_parse.h"
#include "tcc.h"

extern int tcc_sym_push(char *typename, int typesize, int meta);

/* parse C code and return it in key-value form */

static void __appendString(const char *msg, char **s) {
	if (!s) {
		printf ("%s\n", msg);
	} else if (*s) {
		char *p = malloc (strlen (msg) + strlen (*s) + 1);
		if (p) {
			strcpy (p, *s);
			free (*s);
			*s = p;
			strcpy (p + strlen (p), msg);
		}
	} else {
		*s = strdup (msg);
	}
}

static bool __typeLoad(void *p, const char *k, const char *v) {
	if (!p) {
		return false;
	}
	int btype = 0;
	RAnal *anal = (RAnal*)p;
	//r_cons_printf ("tk %s=%s\n", k, v);
	// TODO: Add unions support
	if (!strncmp (v, "struct", 6) && strncmp (k, "struct.", 7)) {
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
	return true;
}

static void __errorFunc(void *opaque, const char *msg) {
	__appendString (msg, opaque);
	char **p = (char **)opaque;
	if (p && *p) {
		int n = strlen(*p);
		char *ptr = malloc (n + 2);
		if (!ptr) {
			return;
		}
		strcpy (ptr, *p);
		ptr[n] = '\n';
		ptr[n + 1] = 0;
		free (*p);
		*p = ptr;
	}
}

R_API char *r_parse_c_file(RAnal *anal, const char *path, const char *dir, char **error_msg) {
	char *str = NULL;
	TCCState *T = tcc_new (anal->cpu, anal->bits, anal->os);
	if (!T) {
		return NULL;
	}
	tcc_set_callback (T, &__appendString, &str);
	tcc_set_error_func (T, (void *)error_msg, __errorFunc);
	sdb_foreach (anal->sdb_types, __typeLoad, anal);
	if (tcc_add_file (T, path, dir) == -1) {
		free (str);
		str = NULL;
	}
	tcc_delete (T);
	return str;
}

R_API char *r_parse_c_string(RAnal *anal, const char *code, char **error_msg) {
	char *str = NULL;
	TCCState *T = tcc_new (anal->cpu, anal->bits, anal->os);
	if (!T) {
		return NULL;
	}
	tcc_set_callback (T, &__appendString, &str);
	tcc_set_error_func (T, (void *)error_msg, __errorFunc);
	sdb_foreach (anal->sdb_types, __typeLoad, NULL);
	if (tcc_compile_string (T, code) != 0) {
		free (str);
		str = NULL;
	}
	tcc_delete (T);
	return str;
}

// XXX do not use globals
R_API void r_parse_c_reset(RParse *p) {
	anon_sym = SYM_FIRST_ANOM;
}
