/* radare - LGPL - Copyright 2013-2022 - pancake */

#include "r_util.h"
#include "r_types.h"
#include "r_parse.h"
#define ONE_SOURCE 1
#include "tcc.h"
#include "c/tccgen.c"
#include "c/tccpp.c"
#include "c/libtcc.c"

static R_TH_LOCAL RThreadLock r_tcc_lock = R_THREAD_LOCK_INIT;
static R_TH_LOCAL TCCState *s1 = NULL;
extern int tcc_sym_push(TCCState *s1, char *typename, int typesize, int meta);

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

// NOTE: must hold r_tcc_lock
static bool __typeLoad(void *p, const char *k, const char *v) {
	r_strf_buffer (128);
	if (!p) {
		return false;
	}
	int btype = 0;
	RAnal *anal = (RAnal*)p;
	// TCCState *s1 = NULL; // XXX THIS WILL MAKE IT CRASH
	//r_cons_printf ("tk %s=%s\n", k, v);
	// TODO: Add unions support
	if (!strncmp (v, "struct", 6) && strncmp (k, "struct.", 7)) {
		// structure
		btype = VT_STRUCT;
		const char *typename = k;
		int typesize = 0;
		// TODO: Add typesize here
		char* query = r_strf ("struct.%s", k);
		char *members = sdb_get (anal->sdb_types, query, 0);
		char *next, *ptr = members;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				query = r_strf ("struct.%s.%s", k, name);
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
					query = r_strf ("struct.%s.%s.meta", subtype, subname);
					btype = sdb_num_get (anal->sdb_types, query, 0);
					tcc_sym_push (s1, subtype, 0, btype);
				}
				free (subtype);
				ptr = next;
			} while (next);
			free (members);
		}
		tcc_sym_push (s1, (char *)typename, typesize, btype);
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
	r_th_lock_enter (&r_tcc_lock);
	TCCState *T = tcc_new (anal->config->cpu, anal->config->bits, anal->config->os);
	if (!T) {
		r_th_lock_leave (&r_tcc_lock);
		return NULL;
	}
	s1 = T; // XXX delete global
	tcc_set_callback (T, &__appendString, &str);
	tcc_set_error_func (T, (void *)error_msg, __errorFunc);
	sdb_foreach (anal->sdb_types, __typeLoad, anal); // why is this needed??
	char *d = strdup (dir);
	RList *dirs = r_str_split_list (d, ":", 0);
	RListIter *iter;
	char *di;
	bool found = false;
	r_list_foreach (dirs, iter, di) {
		if (tcc_add_file (T, path, di) != -1) {
			found = true;
			break;
		}
	}
	if (!found) {
		R_FREE (str);
	}
	r_list_free (dirs);
	free (d);
	tcc_delete (T);
	r_th_lock_leave (&r_tcc_lock);
	return str;
}

R_API char *r_parse_c_string(RAnal *anal, const char *code, char **error_msg) {
	char *str = NULL;
	r_th_lock_enter (&r_tcc_lock);
	TCCState *T = tcc_new (anal->config->arch, anal->config->bits, anal->config->os);
	if (!T) {
		TCCState *T = tcc_new (R_SYS_ARCH, R_SYS_BITS, R_SYS_OS);
		if (!T) {
			R_LOG_ERROR ("Cannot instantiate TCC for given arch (%s)", anal->config->arch);
			r_th_lock_leave (&r_tcc_lock);
			return NULL;
		}
	}
	s1 = T; // XXX delete global
	tcc_set_callback (T, &__appendString, &str);
	tcc_set_error_func (T, (void *)error_msg, __errorFunc);
	sdb_foreach (anal->sdb_types, __typeLoad, NULL);
	if (tcc_compile_string (T, code) != 0) {
		R_FREE (str);
	}
	tcc_delete (T);
	r_th_lock_leave (&r_tcc_lock);
	return str;
}
