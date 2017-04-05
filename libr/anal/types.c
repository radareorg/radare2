/* radare - LGPL - Copyright 2013-2016 - pancake, oddcoder */

#include "r_anal.h"

R_API int r_anal_type_set(RAnal *anal, ut64 at, const char *field, ut64 val) {
	Sdb *DB = anal->sdb_types;
	const char *kind;
	char var[128];
	sprintf (var, "link.%08"PFMT64x, at);
	kind = sdb_const_get (DB, var, NULL);
	if (kind) {
		const char *p = sdb_const_get (DB, kind, NULL);
		if (p) {
			snprintf (var, sizeof (var), "%s.%s.%s", p, kind, field);
			int off = sdb_array_get_num (DB, var, 1, NULL);
			//int siz = sdb_array_get_num (DB, var, 2, NULL);
			eprintf ("wv 0x%08"PFMT64x" @ 0x%08"PFMT64x, val, at+off);
			return true;
		}
		eprintf ("Invalid kind of type\n");
	}
	return false;
}

R_API void r_anal_type_del(RAnal *anal, const char *name) {
	Sdb *db = anal->sdb_types;
	const char *kind = sdb_const_get (db, name, 0);
	if (!kind) {
		return;
	}
	if (!strcmp (kind, "type")) {
		sdb_unset (db, sdb_fmt (-1, "type.%s", name), 0);
		sdb_unset (db, sdb_fmt (-1, "type.%s.size", name), 0);
		sdb_unset (db, sdb_fmt (-1, "type.%s.meta", name), 0);
		sdb_unset (db, name, 0);
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		int i, n = sdb_array_length(db, sdb_fmt (-1, "%s.%s", kind, name));
		char *elements_key = r_str_newf ("%s.%s", kind, name);
		for (i = 0; i< n; i++) {
			char *p = sdb_array_get (db, elements_key, i, NULL);
			sdb_unset (db, sdb_fmt (-1, "%s.%s", elements_key, p), 0);
			free (p);
		}
		sdb_unset (db, elements_key, 0);
		sdb_unset (db, name, 0);
		free (elements_key);
	} else if (!strcmp (kind, "func")) {
		int i, n = sdb_num_get (db, sdb_fmt(-1, "func.%s.args", name), 0);
		for (i = 0; i < n; i++) {
			sdb_unset (db, sdb_fmt(-1, "func.%s.arg.%d", name, i), 0);
		}
		sdb_unset (db, sdb_fmt(-1, "func.%s.ret", name), 0);
		sdb_unset (db, sdb_fmt(-1, "func.%s.cc", name), 0);
		sdb_unset (db, sdb_fmt(-1, "func.%s.noreturn", name), 0);
		sdb_unset (db, sdb_fmt(-1, "func.%s.args", name), 0);
		sdb_unset (db, name, 0);
	} else if (!strcmp (kind, "enum")) {
		int i;
		for (i=0;; i++) {
			const char *tmp = sdb_const_get (db, sdb_fmt (-1, "%s.0x%x", name, i), 0);
			if (!tmp) {
				break;
			}
			sdb_unset (db, sdb_fmt (-1, "%s.%s", name, tmp), 0);
			sdb_unset (db, sdb_fmt (-1, "%s.0x%x", name, i), 0);
		}
		sdb_unset (db, name, 0);
	} else {
		eprintf ("Unrecognized type \"%s\"\n", kind);
	}
}

R_API int r_anal_type_get_size(RAnal *anal, const char *type) {
	char *query;
	const char *t = sdb_const_get (anal->sdb_types, type, 0);
	if (!t) {
		return 0;
	}
	if (!strcmp (t, "type")){
		query = sdb_fmt (-1, "type.%s.size", type);
		return sdb_num_get (anal->sdb_types, query, 0);
	}
	if (!strcmp (t, "struct")) {
		query = sdb_fmt (-1, "struct.%s", type);
		char *members = sdb_get (anal->sdb_types, query, 0);
		char *next, *ptr = members;
		int ret = 0;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				query = sdb_fmt (-1, "struct.%s.%s", type, name);
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
					int elements = r_num_math (NULL, tmp);
					if (elements == 0) {
						elements = 1;
					}
					ret += r_anal_type_get_size (anal, subtype) * elements;
				}
				free (subtype);
				ptr = next;
			} while (next);
			free (members);
		}
		return ret;
	}
	return 0;
}

R_API char* r_anal_type_to_str (RAnal *a, const char *type) {
	// convert to C text... maybe that should be in format string..
	return NULL;
}

R_API RList *r_anal_type_list_new() {
	return NULL;
}

R_API void r_anal_type_header (RAnal *anal, const char *hdr) {
}

R_API void r_anal_type_define (RAnal *anal, const char *key, const char *value) {

}

R_API int r_anal_type_link(RAnal *anal, const char *type, ut64 addr) {
	if (sdb_const_get (anal->sdb_types, type, 0)) {
		char *laddr = r_str_newf ("link.%08"PFMT64x, addr);
		sdb_set (anal->sdb_types, laddr, type, 0);
		free (laddr);
		return true;
	}
	// eprintf ("Cannot find type\n");
	return false;
}

R_API int r_anal_type_unlink(RAnal *anal, ut64 addr) {
	char *laddr = sdb_fmt (-1, "link.%08"PFMT64x, addr);
	sdb_unset (anal->sdb_types, laddr, 0);
	return true;
}

static void filter_type(char *t) {
	for (;*t; t++) {
		if (*t == ' ') {
			*t = '_';
		}
		// memmove (t, t+1, strlen (t));
	}
}

R_API char *r_anal_type_format(RAnal *anal, const char *t) {
	int n;
	char *p, var[128], var2[128], var3[128];
	char *fmt = NULL;
	char *vars = NULL;
	Sdb *DB = anal->sdb_types;
	const char *kind = sdb_const_get (DB, t, NULL);
	if (!kind) return NULL;
	// only supports struct atm
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_get (DB, var, NULL);
		if (fmt)
			return strdup (fmt);
	} else
	if (!strcmp (kind, "struct")) {
		// assumes var list is sorted by offset.. should do more checks here
		for (n = 0; (p = sdb_array_get (DB, var, n, NULL)); n++) {
			const char *tfmt;
			char *type;
			int elements;
			//int off;
			//int size;
			bool isStruct = false;
			bool isEnum = false;
			snprintf (var2, sizeof (var2), "%s.%s", var, p);
			type = sdb_array_get (DB, var2, 0, NULL);
			if (type) {
				//off = sdb_array_get_num (DB, var2, 1, NULL);
				//size = sdb_array_get_num (DB, var2, 2, NULL);
				if (!strncmp (type, "struct ", 7)) {
					char* struct_name = type + 7;
					// TODO: iterate over all the struct fields, and format the format and vars
					snprintf (var3, sizeof (var3), "struct.%s", struct_name);
					fmt = r_str_append (fmt, "?");
					vars = r_str_appendf (vars, "(%s)%s", struct_name, p);
					vars = r_str_append (vars, " ");
				} else {
					elements = sdb_array_get_num (DB, var2, 2, NULL);
					// special case for char[]. Use char* format type without *
					if (!strncmp (type, "char", 5) && elements > 0) {
						tfmt = sdb_const_get (DB, "type.char *", NULL);
						if (tfmt && *tfmt == '*') {
							tfmt++;
						}
					} else {
						if (!strncmp (type, "enum ", 5)) {
							snprintf (var3, sizeof (var3), "%s", type + 5);
							isEnum = true;
						} else if (!strncmp (type, "struct ", 7)) {
							snprintf (var3, sizeof (var3), "%s", type + 7);
							isStruct = true;
						} else {
							snprintf (var3, sizeof (var3), "type.%s", type);
						}
						tfmt = sdb_const_get (DB, var3, NULL);
					}
					if (tfmt) {
						filter_type (type);
						if (elements > 0) {
							fmt = r_str_appendf (fmt, "[%d]", elements);
						}
						if (isStruct) {
							fmt = r_str_append (fmt, "?");
							vars = r_str_appendf (vars, "(%s)%s", p, p);
							vars = r_str_append (vars, " ");
						} else if (isEnum) {
							fmt = r_str_append (fmt, "E");
							vars = r_str_appendf (vars, "(%s)%s", type + 5, p);
							vars = r_str_append (vars, " ");
						} else {
							fmt = r_str_append (fmt, tfmt);
							vars = r_str_append (vars, p);
							vars = r_str_append (vars, " ");
						}
					} else {
						eprintf ("Cannot resolve type '%s'\n", var3);
					}
				}
			}
			free (type);
			free (p);
		}
		fmt = r_str_append (fmt, " ");
		fmt = r_str_append (fmt, vars);
		free (vars);
		return fmt;
	}
	return NULL;
}
// Function prototypes api
R_API int r_anal_type_func_exist(RAnal *anal, const char *func_name) {
	const char *fcn = sdb_const_get (anal->sdb_types, func_name, 0);
	return fcn && !strcmp (fcn, "func");
}

R_API const char *r_anal_type_func_ret(RAnal *anal, const char *func_name){
	const char *query = sdb_fmt (-1, "func.%s.ret", func_name);
	return sdb_const_get (anal->sdb_types, query, 0);
}

R_API const char *r_anal_type_func_cc(RAnal *anal, const char *func_name) {
	const char *query = sdb_fmt (-1, "func.%s.cc", func_name);
	const char *cc = sdb_const_get (anal->sdb_types, query, 0);
	return cc ? cc : r_anal_cc_default (anal);
}

R_API int r_anal_type_func_args_count(RAnal *anal, const char *func_name) {
	const char *query = sdb_fmt (-1, "func.%s.args", func_name);
	return sdb_num_get (anal->sdb_types, query, 0);
}

R_API char *r_anal_type_func_args_type(RAnal *anal, const char *func_name, int i) {
	const char *query = sdb_fmt (-1, "func.%s.arg.%d", func_name, i);
	char *ret = sdb_get (anal->sdb_types, query, 0);
	if (ret) {
		char *comma = strchr (ret, ',');
		if (comma) {
			*comma = 0;
			return ret;
		}
		free (ret);
	}
	return NULL;
}

R_API char *r_anal_type_func_args_name(RAnal *anal, const char *func_name, int i) {
	const char *query = sdb_fmt (-1, "func.%s.arg.%d", func_name, i);
	const char *get = sdb_const_get (anal->sdb_types, query, 0);
	if (get) {
		char *ret = strchr (get, ',');
		return ret == 0 ? ret : ret + 1;
	}
	return NULL;
}

#define MIN_MATCH_LEN 4

// TODO: Future optimizations
// - symbol names are long and noisy, reduce searchspace for match here
//   by preprocessing to delete noise, as much as we can.
// - We ignore all func.*, but thats maybe most of sdb entries
//   could maybe eliminate this work (strcmp).
R_API char *r_anal_type_func_guess(RAnal *anal, char *func_name) {
	int j = 0, offset = 0, n;
	char *str = func_name;

	if (!func_name) {
		return NULL;
	}

	size_t slen = strlen (str);
	if (slen < MIN_MATCH_LEN) {
		return NULL;
	}

	if(slen > 4) { // were name-matching so ignore autonamed
		if ((str[0] == 'f' && str[1] == 'c' && str[2] == 'n' && str[3] == '.') ||
			(str[0] == 'l' && str[1] == 'o' && str[2] == 'c' && str[3] == '.') ) {
			return NULL;
		}
	}
	// strip r2 prefixes (sym, sym.imp, etc')
	while(slen > 4 && (offset + 3 < slen ) && str[offset + 3] == '.') {
		offset+=4;
	}
	slen -= offset;
	str = strdup (&func_name[offset]);
	for (n = slen; n >= MIN_MATCH_LEN; --n) {
		for (j = 0; j < slen - (n - 1); ++j) {
			char saved = str[j + n];
			str[j + n] = 0;
			if (sdb_exists (anal->sdb_types, &str[j])) {
				const char *res = sdb_const_get (anal->sdb_types, &str[j], 0);
				bool is_func = res && !strcmp ("func", res);
				if (is_func) {
					return strdup (&str[j]);
				}
			}
			str[j + n] = saved;
		}
	}
	return NULL;
}
