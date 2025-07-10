/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_asm.h>
#include "c/tcc.h"
#include "c/tccgen.c"
#include "c/tccpp.c"
#include "c/libtcc.c"
#define USE_R2 1
#include <spp/spp.h>

// used to pass anal and s1 to loader
typedef struct {
	RAnal *anal;
	TCCState *s1;
} LoadContext;

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

static bool __typeLoad(void *p, const char *k, const char *v) {
	r_strf_buffer (128);
	if (!p) {
		return false;
	}
	int btype = 0;
	LoadContext *loader = (LoadContext *)p;
	RAnal *anal = loader->anal;
	TCCState *s1 = loader->s1;
	// TCCState *s1 = NULL; // XXX THIS WILL MAKE IT CRASH
	//r_cons_printf (cons, "tk %s=%s\n", k, v);
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

R_IPI char* kvc_parse(const char* header_content, char **errmsg);

R_API char *r_anal_cparse2(RAnal *anal, const char *code, char **error_msg) {
	return kvc_parse (code, error_msg);
}

static TCCState *new_tcc(RAnal *anal) {
	TCCState *ts = tcc_new (anal->config->arch, anal->config->bits, anal->config->os);
	if (!ts) {
		ts = tcc_new (R_SYS_ARCH, R_SYS_BITS, R_SYS_OS);
		if (!ts) {
			R_LOG_ERROR ("Cannot instantiate TCC for given arch (%s)", anal->config->arch);
			return NULL;
		}
	}
	return ts;
}

R_API char *r_anal_cparse_file(RAnal *anal, const char *path, const char *dir, char **error_msg) {
	if (anal->opt.newcparser) {
		char *code = r_file_slurp (path, NULL);
		if (code) {
			char *res = r_anal_cparse2 (anal, code, error_msg);
			free (code);
			return res;
		}
	}
	char *str = NULL;
	TCCState *s1 = new_tcc (anal);
	if (!s1) {
		return NULL;
	}
	tcc_set_callback (s1, &__appendString, &str);
	tcc_set_error_func (s1, (void *)error_msg, __errorFunc);

	// load saved types from sdb into the tcc context
	LoadContext ctx = {anal, s1};
	sdb_foreach (anal->sdb_types, __typeLoad, (void *)&ctx);

	char *d = strdup (dir);
	RList *dirs = r_str_split_list (d, ":", 0);
	RListIter *iter;
	char *di;
	bool found = false;
	r_list_foreach (dirs, iter, di) {
		if (tcc_add_file (s1, path, di) != -1) {
			found = true;
			break;
		}
	}
	if (!found) {
		R_FREE (str);
	}
	r_list_free (dirs);
	free (d);
	tcc_delete (s1);
	return str;
}

R_API char *r_anal_cparse(RAnal *anal, const char *code, char **error_msg) {
	if (anal->opt.newcparser) {
		return r_anal_cparse2 (anal, code, error_msg);
	}
	char *str = NULL;
	TCCState *s1 = new_tcc (anal);
	if (!s1) {
		R_LOG_ERROR ("Cannot instantiate TCC for given arch (%s)", anal->config->arch);
		return NULL;
	}
	tcc_set_callback (s1, &__appendString, &str);
	tcc_set_error_func (s1, (void *)error_msg, __errorFunc);

	// load saved types from sdb into the tcc context
	LoadContext ctx = {anal, s1};
	sdb_foreach (anal->sdb_types, __typeLoad, (void *)&ctx);

	if (tcc_compile_string (s1, code) != 0) {
		R_FREE (str);
	}
	tcc_delete (s1);
	return str;
}
