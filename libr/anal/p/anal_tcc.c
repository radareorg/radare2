/* radare - LGPL - Copyright 2025 - pancake */

#include <r_anal.h>
#include "../c/tcc.h"
#include "../c/tccgen.c"
#include "../c/tccpp.c"
#include "../c/libtcc.c"
#define USE_R2 1
#include <spp/spp.h>


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

static void __errorFunc(void *opaque, const char *msg) {
	__appendString (msg, opaque);
	char **p = (char **)opaque;
	if (R_STR_ISNOTEMPTY (p)) {
		int n = strlen (*p);
		char *ptr = malloc (n + 2);
		if (ptr) {
			strcpy (ptr, *p);
			ptr[n] = '\n';
			ptr[n + 1] = 0;
			free (*p);
			*p = ptr;
		}
	}
}

// used to pass anal and s1 to loader
typedef struct {
	RAnal *anal;
	TCCState *s1;
} LoadContext;

extern int tcc_sym_push(TCCState *s1, char *typename, int typesize, int meta);

/* parse C code and return it in key-value form */

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


static char *types_parse_text(RAnal *anal, const char *code) {
	char **error_msg = NULL;
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
	if (error_msg) {
		R_LOG_ERROR ("tcc: %s", error_msg);
		free (error_msg);
	}
	return str;
}

static char *types_parse_file(RAnal *anal, const char *path, const char *dir) {
	char *str = NULL;
	TCCState *s1 = new_tcc (anal);
	if (!s1) {
		return NULL;
	}
	char **error_msg = NULL;
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
	if (error_msg) {
		R_LOG_ERROR ("tcc: %s", error_msg);
		free (error_msg);
	}
	return str;
}

RAnalPlugin r_anal_plugin_tcc = {
	.meta = {
		.name = "tcc",
		.desc = "",
		.license = "LGPL3",
	},
	.tparse_text = types_parse_text,
	.tparse_file = types_parse_file,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tcc,
	.version = R2_VERSION
};
#endif
