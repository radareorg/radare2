/* radare - LGPL - Copyright 2013-2018 - pancake, oddcoder, sivaramaaa */

#include "r_util.h"

R_API int r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val) {
	const char *kind;
	char var[128];
	sprintf (var, "link.%08"PFMT64x, at);
	kind = sdb_const_get (TDB, var, NULL);
	if (kind) {
		const char *p = sdb_const_get (TDB, kind, NULL);
		if (p) {
			snprintf (var, sizeof (var), "%s.%s.%s", p, kind, field);
			int off = sdb_array_get_num (TDB, var, 1, NULL);
			//int siz = sdb_array_get_num (DB, var, 2, NULL);
			eprintf ("wv 0x%08"PFMT64x" @ 0x%08"PFMT64x, val, at+off);
			return true;
		}
		eprintf ("Invalid kind of type\n");
	}
	return false;
}

R_API bool r_type_isenum(Sdb *TDB, const char *name) {
	if (!name) {
		return false;
	}
	const char *type = sdb_const_get (TDB, name, 0);
	if (type && !strcmp (type, "enum")) {
		return true;
	} else {
		return false;
	}
}

R_API RList* r_type_get_enum (Sdb *TDB, const char *name) {
	char *p, *val, var[128], var2[128];
	int n;

	if (!r_type_isenum (TDB, name)) {
		return NULL;
	}
	RList *res = r_list_new ();
	snprintf (var, sizeof (var), "enum.%s", name);
	for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
		RTypeEnum *member = R_NEW0 (RTypeEnum);
		snprintf (var2, sizeof (var2), "%s.%s", var, p);
		val = sdb_array_get (TDB, var2, 0, NULL);
		member->name = p;
		member->val = val;
		r_list_append (res, member);
	}
	return res;
}

R_API char *r_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val) {
	const char *q;
	if (!r_type_isenum (TDB, name)) {
		return NULL;
	}
	if (member) {
		q = sdb_fmt ("enum.%s.%s", name, member);
	} else {
		q = sdb_fmt ("enum.%s.0x%x", name, val);
	}
	return sdb_get (TDB, q, 0);
}

R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val) {
	char *q, *ret = NULL;
	const char *res;
	int i;

	if (!r_type_isenum (TDB, name)) {
		return NULL;
	}
	bool isFirst = true;
	ret = r_str_appendf (ret, "0x%08"PFMT64x" : ", val);
	for (i = 0; i < 32; i++) {
		if (!(val & (1 << i))) {
			continue;
		}
		q = sdb_fmt ("enum.%s.0x%x", name, (1<<i));
                res = sdb_const_get (TDB, q, 0);
                if (isFirst) {
			isFirst = false;
                } else {
			ret = r_str_append (ret, " | ");
                }
                if (res) {
			ret = r_str_append (ret, res);
                } else {
			ret = r_str_appendf (ret, "0x%x", (1<<i));
                }
	}
	return ret;
}

R_API int r_type_get_bitsize(Sdb *TDB, const char *type) {
	char *query;
	/* Filter out the structure keyword if type looks like "struct mystruc" */
	const char *tmptype;
	if (!strncmp (type, "struct ", 7)) {
		tmptype = type + 7;
	} else {
		tmptype = type;
	}
	const char *t = sdb_const_get (TDB, tmptype, 0);
	if (!t) {
		if (!strncmp (tmptype, "enum ", 5)) {
			//XXX: Need a proper way to determine size of enum
			return 32;
		}
		return 0;
	}
	if (!strcmp (t, "type")){
		query = sdb_fmt ("type.%s.size", tmptype);
		return sdb_num_get (TDB, query, 0); // returns size in bits
	}
	if (!strcmp (t, "struct")) {
		query = sdb_fmt ("struct.%s", tmptype);
		char *members = sdb_get (TDB, query, 0);
		char *next, *ptr = members;
		int ret = 0;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				query = sdb_fmt ("struct.%s.%s", tmptype, name);
				char *subtype = sdb_get (TDB, query, 0);
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
					ret += r_type_get_bitsize (TDB, subtype) * elements;
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

R_API char *r_type_get_struct_memb(Sdb *TDB, const char *type, int offset) {
	char* query = sdb_fmt ("struct.%s", type);
	char *members = sdb_get (TDB, query, 0);
	int i, typesize = 0;
	char *res = NULL;
	if (!members) {
		eprintf ("%s is not a struct\n", type);
		return NULL;
	}
	int nargs = r_str_split (members, ',');
	for (i = 0; i < nargs ; i++) {
		const char *name = r_str_word_get0 (members, i);
		if (!name) {
			break;
		}
		query = sdb_fmt ("struct.%s.%s", type, name);
		char *subtype = sdb_get (TDB, query, 0);
		if (!subtype) {
			break;
		}
		if (r_str_split (subtype, ',') != 3) {
			free (subtype);
			break;
		}
		int val = r_num_math (NULL, r_str_word_get0 (subtype, 2));
		int arrsz = val ? val : 1;
		if ((typesize / 8) == offset) {
			res = sdb_fmt ("%s.%s", type, name);
			free (subtype);
			break;
		}
		typesize += r_type_get_bitsize (TDB, subtype) * arrsz;
		free (subtype);
	}
	free (members);
	return res;
}

R_API RList* r_type_get_by_offset(Sdb *TDB, ut64 offset) {
	RList *offtypes = r_list_new ();
	SdbList *ls = sdb_foreach_list (TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		// TODO: Add unions support
		if (!strncmp (kv->value, "struct", 6) && strncmp (kv->key, "struct.", 7)) {
			char *res = r_type_get_struct_memb (TDB, kv->key, offset);
			r_list_append (offtypes, res);
		}
	}
	ls_free (ls);
	return offtypes;
}

R_API char *r_type_link_at (Sdb *TDB, ut64 addr) {
	char* query = sdb_fmt ("link.%08"PFMT64x, addr);
	return sdb_get (TDB, query, 0);
}

R_API int r_type_set_link(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		char *laddr = r_str_newf ("link.%08"PFMT64x, addr);
		sdb_set (TDB, laddr, type, 0);
		free (laddr);
		return true;
	}
	// eprintf ("Cannot find type\n");
	return false;
}

R_API int r_type_link_offset(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		char *laddr = r_str_newf ("offset.%08"PFMT64x, addr);
		sdb_set (TDB, laddr, type, 0);
		free (laddr);
		return true;
	}
	// eprintf ("Cannot find type\n");
	return false;
}

R_API int r_type_unlink(Sdb *TDB, ut64 addr) {
	char *laddr = sdb_fmt ("link.%08"PFMT64x, addr);
	sdb_unset (TDB, laddr, 0);
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

R_API char *r_type_format(Sdb *TDB, const char *t) {
	int n;
	char *p, var[128], var2[128], var3[128];
	char *fmt = NULL;
	char *vars = NULL;
	const char *kind = sdb_const_get (TDB, t, NULL);
	if (!kind) return NULL;
	// only supports struct atm
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_get (TDB, var, NULL);
		if (fmt)
			return strdup (fmt);
	} else
	if (!strcmp (kind, "struct")) {
		// assumes var list is sorted by offset.. should do more checks here
		for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
			const char *tfmt;
			char *type;
			char *struct_name;
			bool isStruct = false;
			bool isEnum = false;
			snprintf (var2, sizeof (var2), "%s.%s", var, p);
			type = sdb_array_get (TDB, var2, 0, NULL);
			int elements = sdb_array_get_num (TDB, var2, 2, NULL);
			if (type) {
				//off = sdb_array_get_num (DB, var2, 1, NULL);
				//size = sdb_array_get_num (DB, var2, 2, NULL);
				if (!strncmp (type, "struct ", 7)) {
					struct_name = type + 7;
					// TODO: iterate over all the struct fields, and format the format and vars
					snprintf (var3, sizeof (var3), "struct.%s", struct_name);
					tfmt = sdb_const_get (TDB, var3, NULL);
					isStruct = true;
				} else {
					// special case for char[]. Use char* format type without *
					if (!strncmp (type, "char", 5) && elements > 0) {
						tfmt = sdb_const_get (TDB, "type.char *", NULL);
						if (tfmt && *tfmt == '*') {
							tfmt++;
						}
					} else {
						if (!strncmp (type, "enum ", 5)) {
							snprintf (var3, sizeof (var3), "%s", type + 5);
							isEnum = true;
						} else {
							snprintf (var3, sizeof (var3), "type.%s", type);
						}
						tfmt = sdb_const_get (TDB, var3, NULL);
					}

				}
				if (tfmt) {
					filter_type (type);
					if (elements > 0) {
						fmt = r_str_appendf (fmt, "[%d]", elements);
					}
					if (isStruct) {
						fmt = r_str_append (fmt, "?");
						vars = r_str_appendf (vars, "(%s)%s", struct_name, p);
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

R_API void r_type_del(Sdb *TDB, const char *name) {
	const char *kind = sdb_const_get (TDB, name, 0);
	if (!kind) {
		return;
	}
	if (!strcmp (kind, "type")) {
		sdb_unset (TDB, sdb_fmt ("type.%s", name), 0);
		sdb_unset (TDB, sdb_fmt ("type.%s.size", name), 0);
		sdb_unset (TDB, sdb_fmt ("type.%s.meta", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		int i, n = sdb_array_length(TDB, sdb_fmt ("%s.%s", kind, name));
		char *elements_key = r_str_newf ("%s.%s", kind, name);
		for (i = 0; i< n; i++) {
			char *p = sdb_array_get (TDB, elements_key, i, NULL);
			sdb_unset (TDB, sdb_fmt ("%s.%s", elements_key, p), 0);
			free (p);
		}
		sdb_unset (TDB, elements_key, 0);
		sdb_unset (TDB, name, 0);
		free (elements_key);
	} else if (!strcmp (kind, "func")) {
		int i, n = sdb_num_get (TDB, sdb_fmt ("func.%s.args", name), 0);
		for (i = 0; i < n; i++) {
			sdb_unset (TDB, sdb_fmt ("func.%s.arg.%d", name, i), 0);
		}
		sdb_unset (TDB, sdb_fmt ("func.%s.ret", name), 0);
		sdb_unset (TDB, sdb_fmt ("func.%s.cc", name), 0);
		sdb_unset (TDB, sdb_fmt ("func.%s.noreturn", name), 0);
		sdb_unset (TDB, sdb_fmt ("func.%s.args", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "enum")) {
		RList *list = r_type_get_enum (TDB, name);
		RTypeEnum *member;
		RListIter *iter;
		r_list_foreach (list, iter, member) {
			sdb_unset (TDB, sdb_fmt ("enum.%s.%s", name, member->name), 0);
			sdb_unset (TDB, sdb_fmt ("enum.%s.0x%x", name, member->val), 0);
		}
		sdb_unset (TDB, name, 0);
	} else {
		eprintf ("Unrecognized type \"%s\"\n", kind);
	}
}

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name) {
	const char *fcn = sdb_const_get (TDB, func_name, 0);
	return fcn && !strcmp (fcn, "func");
}

R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name){
	const char *query = sdb_fmt ("func.%s.ret", func_name);
	return sdb_const_get (TDB, query, 0);
}

R_API int r_type_func_args_count(Sdb *TDB, const char *func_name) {
	const char *query = sdb_fmt ("func.%s.args", func_name);
	return sdb_num_get (TDB, query, 0);
}

R_API char *r_type_func_args_type(Sdb *TDB, const char *func_name, int i) {
	const char *query = sdb_fmt ("func.%s.arg.%d", func_name, i);
	char *ret = sdb_get (TDB, query, 0);
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

R_API char *r_type_func_args_name(Sdb *TDB, const char *func_name, int i) {
	const char *query = sdb_fmt ("func.%s.arg.%d", func_name, i);
	const char *get = sdb_const_get (TDB, query, 0);
	if (get) {
		char *ret = strchr (get, ',');
		return ret == 0 ? ret : ret + 1;
	}
	return NULL;
}

#define MIN_MATCH_LEN 4

static char *type_func_try_guess(Sdb *TDB, char *name) {
	const char *res;
	if (r_str_nlen (name, MIN_MATCH_LEN) < MIN_MATCH_LEN) {
		return NULL;
	}
	if ((res = sdb_const_get (TDB, name, NULL))) {
		bool is_func = res && !strcmp ("func", res);
		if (is_func) {
			return strdup (name);
		}
	}
	return NULL;
}

// TODO:
// - symbol names are long and noisy, some of them might not be matched due
//   to additional information added around name
R_API char *r_type_func_guess(Sdb *TDB, char *func_name) {
	int offset = 0;
	char *str = func_name;
	char *result = NULL;
	char *first, *last;
	if (!func_name) {
		return NULL;
	}

	size_t slen = strlen (str);
	if (slen < MIN_MATCH_LEN) {
		return NULL;
	}

	if (slen > 4) { // were name-matching so ignore autonamed
		if ((str[0] == 'f' && str[1] == 'c' && str[2] == 'n' && str[3] == '.') ||
		    (str[0] == 'l' && str[1] == 'o' && str[2] == 'c' && str[3] == '.')) {
			return NULL;
		}
	}
	// strip r2 prefixes (sym, sym.imp, etc')
	while (slen > 4 && (offset + 3 < slen) && str[offset + 3] == '.') {
		offset += 4;
	}
	slen -= offset;
	str += offset;
	if ((result = type_func_try_guess (TDB, str))) {
		return result;
	}
	str = strdup (str);
	// some names are in format module.dll_function_number, try to remove those
	// also try module.dll_function and function_number
	if ((first = strchr (str, '_'))) {
		last = (char *)r_str_lchr (first, '_');
		if (!last) {
			goto out;
		}
		// middle + suffix or right half
		if ((result = type_func_try_guess (TDB, first + 1))) {
			goto out;
		}
		last[0] = 0;
		// prefix + middle or left
		if ((result = type_func_try_guess (TDB, str))) {
			goto out;
		}
		if (last != first) {
			// middle
			if ((result = type_func_try_guess (TDB, first + 1))) {
				goto out;
			}
		}
		result = NULL;
	}
out:
	free (str);
	return result;
}
