/* radare - LGPL - Copyright 2013-2025 - pancake, oddcoder, sivaramaaa */

// R2R db/cmd/types

#include <r_util.h>

R_API bool r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val) {
	char var[128];
	snprintf (var, sizeof (var), "link.%08" PFMT64x, at);
	const char *kind = sdb_const_get (TDB, var, NULL);
	if (kind) {
		const char *p = sdb_const_get (TDB, kind, NULL);
		if (p) {
			char *v = r_str_newf ("%s.%s.%s", p, kind, field);
			int off = sdb_array_get_num (TDB, v, 1, NULL);
			free (v);
			// int siz = sdb_array_get_num (DB, var, 2, NULL);
			eprintf ("wv 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", val, at + off);
			return true;
		}
		R_LOG_ERROR ("Invalid kind of type");
	}
	return false;
}

R_API RTypeKind r_type_kind(Sdb *TDB, const char *name) {
	R_RETURN_VAL_IF_FAIL (TDB && R_STR_ISNOTEMPTY (name), -1);
	const char *type = sdb_const_get (TDB, name, 0);
	if (!type) {
		return R_TYPE_INVALID;
	}
	if (!strcmp (type, "enum")) {
		return R_TYPE_ENUM;
	}
	if (!strcmp (type, "struct")) {
		return R_TYPE_STRUCT;
	}
	if (!strcmp (type, "union")) {
		return R_TYPE_UNION;
	}
	if (!strcmp (type, "func")) {
		return R_TYPE_FUNCTION;
	}
	if (!strcmp (type, "type")) {
		return R_TYPE_BASIC;
	}
	if (!strcmp (type, "typedef")) {
		return R_TYPE_TYPEDEF;
	}
	return R_TYPE_INVALID;
}

R_API RList *r_type_get_enum(Sdb *TDB, const char *name) {
	char *p, var[130];
	int n;

	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	RList *res = r_list_newf ( (RListFree)r_type_enum_free);
	snprintf (var, sizeof (var), "enum.%s", name);
	for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
		RTypeEnum *member = R_NEW0 (RTypeEnum);
		if (member) {
			char *var2 = r_str_newf ("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get (TDB, var2, 0, NULL);
				if (val) {
					member->name = p;
					member->val = val;
					r_list_append (res, member);
				} else {
					free (member);
				}
				free (var2);
			} else {
				free (member);
			}
		}
	}
	return res;
}

R_API void r_type_enum_free(RTypeEnum *member) {
	if (member) {
		free (member->name);
		free (member->val);
		free (member);
	}
}

R_API char *r_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val) {
	R_RETURN_VAL_IF_FAIL (TDB && name, NULL);
	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	char *q = member
		? r_str_newf ("enum.%s.%s", name, member)
		: r_str_newf ("enum.%s.0x%" PFMT64x, name, val);
	char *res = sdb_get (TDB, q, 0);
	free (q);
	if (!res) {
		q = r_str_newf ("enum.%s.%" PFMT64d, name, val);
		res = sdb_get (TDB, q, 0);
		free (q);
	}
	return res;
}

R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val) {
	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	bool isFirst = true;
	RStrBuf *sb = r_strbuf_newf ("0x%08" PFMT64x " : ", val);
	int i;
	for (i = 0; i < 32; i++) {
		ut32 n = 1ULL << i;
		if (! (val & n)) {
			continue;
		}
		char *q = r_str_newf ("enum.%s.0x%x", name, n);
		const char *res = sdb_const_get (TDB, q, 0);
		free (q);
		if (isFirst) {
			isFirst = false;
		} else {
			r_strbuf_append (sb, " | ");
		}
		if (res) {
			r_strbuf_append (sb, res);
		} else {
			r_strbuf_appendf (sb, "0x%x", n);
		}
	}
	return r_strbuf_drain (sb);
}

R_API ut64 r_type_get_bitsize(Sdb *TDB, const char *type) {
	/* Filter out the structure keyword if type looks like "struct mystruc" */
	const char *tmptype = type;
	if (r_str_startswith (type, "struct ")) {
		tmptype = type + strlen ("struct ");
	} else if (r_str_startswith (type, "union ")) {
		tmptype = type + strlen ("union ");
	}
	if ((strstr (type, "*(") || strstr (type, " *")) && strcmp (type, "char *")) {
		return 32;
	}
	const char *t = sdb_const_get (TDB, tmptype, 0);
	if (!t) {
		if (r_str_startswith (tmptype, "enum ")) {
			//XXX: Need a proper way to determine size of enum
			return 32;
		}
		return 0;
	}
	if (!strcmp (t, "type")) {
		char *query = r_str_newf ("type.%s.size", tmptype);
		ut64 r = sdb_num_get (TDB, query, 0); // returns size in bits
		free (query);
		return r;
	}
	if (!strcmp (t, "struct") || !strcmp (t, "union")) {
		char *query = r_str_newf ("%s.%s", t, tmptype);
		char *members = sdb_get (TDB, query, 0);
		free (query);
		char *next, *ptr = members;
		ut64 ret = 0;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				char *query = r_str_newf ("%s.%s.%s", t, tmptype, name);
				char *subtype = sdb_get (TDB, query, 0);
				free (query);
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
					if (!strcmp (t, "struct")) {
						ret += r_type_get_bitsize (TDB, subtype) * elements;
					} else {
						ut64 sz = r_type_get_bitsize (TDB, subtype) * elements;
						ret = sz > ret ? sz : ret;
					}
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
	int i, cur_offset, next_offset = 0;
	char *res = NULL;

	if (offset < 0) {
		return NULL;
	}
	char *query = r_str_newf ("struct.%s", type);
	char *members = sdb_get (TDB, query, 0);
	free (query);
	if (!members) {
		// eprintf ("%s is not a struct\n", type);
		return NULL;
	}
	int nargs = r_str_split (members, ',');
	for (i = 0; i < nargs; i++) {
		const char *name = r_str_word_get0 (members, i);
		if (!name) {
			break;
		}
		char *query = r_str_newf ("struct.%s.%s", type, name);
		char *subtype = sdb_get (TDB, query, 0);
		free (query);
		if (!subtype) {
			break;
		}
		int len = r_str_split (subtype, ',');
		if (len < 3) {
			free (subtype);
			break;
		}
		cur_offset = r_num_math (NULL, r_str_word_get0 (subtype, len - 2));
		if (cur_offset > 0 && cur_offset < next_offset) {
			free (subtype);
			break;
		}
		if (!cur_offset) {
			cur_offset = next_offset;
		}
		if (cur_offset == offset) {
			res = r_str_newf ("%s.%s", type, name);
			free (subtype);
			break;
		}
		int arrsz = r_num_math (NULL, r_str_word_get0 (subtype, len - 1));
		int fsize = (r_type_get_bitsize (TDB, subtype) * (arrsz ? arrsz : 1)) / 8;
		if (!fsize) {
			free (subtype);
			break;
		}
		next_offset = cur_offset + fsize;
		// Handle nested structs
		if (offset > cur_offset && offset < next_offset) {
			char *nested_type = (char *)r_str_word_get0 (subtype, 0);
			if (r_str_startswith (nested_type, "struct ") && !r_str_endswith (nested_type, " *")) {
				len = r_str_split (nested_type, ' ');
				if (len < 2) {
					free (subtype);
					break;
				}
				nested_type = (char *)r_str_word_get0 (nested_type, 1);
				char *nested_res = r_type_get_struct_memb (TDB, nested_type, offset - cur_offset);
				if (nested_res) {
					len = r_str_split (nested_res, '.');
					res = r_str_newf ("%s.%s.%s", type, name, r_str_word_get0 (nested_res, len - 1));
					free (nested_res);
					free (subtype);
					break;
				}
			}
		}
		free (subtype);
	}
	free (members);
	return res;
}

// XXX this function is slow!
R_API RList *r_type_get_by_offset(Sdb *TDB, ut64 offset) {
	RList *offtypes = r_list_new ();
	SdbList *ls = sdb_foreach_list (TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		const char *kk = sdbkv_key (kv);
		const char *vv = sdbkv_value (kv);
		// TODO: Add unions support
		if (r_str_startswith (vv, "struct") && !r_str_startswith (kk, "struct.")) {
			char *res = r_type_get_struct_memb (TDB, sdbkv_key (kv), offset);
			if (res) {
				r_list_append (offtypes, res);
			}
		}
	}
	ls_free (ls);
	return offtypes;
}

#define TYPE_RANGE_BASE(x) ( (x) >> 16)

static RList *types_range_list(Sdb *db, ut64 addr) {
	RList *list = NULL;
	ut64 base = TYPE_RANGE_BASE (addr);
	char *s = r_str_newf ("range.%" PFMT64x, base);
	if (s) {
		char *r = sdb_get (db, s, 0);
		if (r) {
			list = r_str_split_list (r, " ", -1);
		}
		free (s);
	}
	return list;
}

static void types_range_del(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE (addr);
	r_strf_var (k, 64, "range.%" PFMT64x, base);
	char valstr[SDB_NUM_BUFSZ];
	const char *v = sdb_itoa (addr, SDB_NUM_BASE, valstr, sizeof (valstr));
	sdb_array_remove (db, k, v, 0);
}

static void types_range_add(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE (addr);
	r_strf_var (k, 64, "range.%" PFMT64x, base);
	(void)sdb_array_add_num (db, k, addr, 0);
}

R_API char *r_type_link_at(Sdb *TDB, ut64 addr) {
	if (addr == UT64_MAX || addr == (UT64_MAX - 1)) {
		return NULL;
	}
	char *query = r_str_newf ("link.%08" PFMT64x, addr);
	char *res = sdb_get (TDB, query, 0);
	free (query);
	if (res) {
		return res;
	}
	// resolve struct memb if possible for given addr
	RList *list = types_range_list (TDB, addr);
	RListIter *iter;
	const char *s;
	r_list_foreach (list, iter, s) {
		ut64 laddr = r_num_get (NULL, s);
		if (addr > laddr) {
			int delta = addr - laddr;
			char *lk = r_str_newf ("link.%08" PFMT64x, laddr);
			char *k = sdb_get (TDB, lk, 0);
			free (lk);
			if (k) {
				char *res = r_type_get_struct_memb (TDB, k, delta);
				if (res) {
					free (k);
					return res;
				}
				free (k);
			}
		}
	}
	r_list_free (list);
	return res;
}

R_API int r_type_set_link(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		char *laddr = r_str_newf ("link.%08" PFMT64x, addr);
		sdb_set (TDB, laddr, type, 0);
		types_range_add (TDB, addr);
		free (laddr);
		return true;
	}
	return false;
}

R_API int r_type_link_offset(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		char *laddr = r_str_newf ("offset.%08" PFMT64x, addr);
		sdb_set (TDB, laddr, type, 0);
		free (laddr);
		return true;
	}
	return false;
}

R_API int r_type_unlink(Sdb *TDB, ut64 addr) {
	char *laddr = r_str_newf ("link.%08" PFMT64x, addr);
	sdb_unset (TDB, laddr, 0);
	free (laddr);
	types_range_del (TDB, addr);
	return true;
}

static char *fmt_struct_union(Sdb *TDB, char *var, bool is_typedef) {
	// assumes var list is sorted by offset.. should do more checks here
	char *p = NULL, var2[132];
	size_t n;
	char *fields = r_str_newf ("%s.fields", var);
	char *nfields = (is_typedef) ? fields : var;
	// TODO: Use RStrBuf for fmt and vars
	RStrBuf *fmt_sb = r_strbuf_new ("");
	RStrBuf *vars_sb = r_strbuf_new ("");
	for (n = 0; (p = sdb_array_get (TDB, nfields, n, NULL)); n++) {
		char *struct_name = NULL;
		const char *tfmt = NULL;
		bool isStruct = false;
		bool isEnum = false;
		bool isfp = false;
		snprintf (var2, sizeof (var2), "%s.%s", var, p);
		size_t alen = sdb_array_size (TDB, var2);
		int elements = sdb_array_get_num (TDB, var2, alen - 1, NULL);
		char *type = sdb_array_get (TDB, var2, 0, NULL);
		if (type) {
			char var3[128] = { 0 };
			// Handle general pointers except for char *
			if ( (strstr (type, "*(") || strstr (type, " *")) && !r_str_startswith (type, "char *")) {
				isfp = true;
			} else if (r_str_startswith (type, "struct ")) {
				struct_name = type + 7;
				// TODO: iterate over all the struct fields, and format the format and vars
				snprintf (var3, sizeof (var3), "struct.%s", struct_name);
				tfmt = sdb_const_get (TDB, var3, NULL);
				isStruct = true;
			} else {
				// special case for char[]. Use char* format type without *
				if (!strcmp (type, "char") && elements > 0) {
					tfmt = sdb_const_get (TDB, "type.char *", NULL);
					if (tfmt && *tfmt == '*') {
						tfmt++;
					}
				} else {
					if (r_str_startswith (type, "enum ")) {
						snprintf (var3, sizeof (var3), "%s", type + 5);
						isEnum = true;
					} else {
						snprintf (var3, sizeof (var3), "type.%s", type);
					}
					tfmt = sdb_const_get (TDB, var3, NULL);
				}
			}
			if (tfmt && !strcmp (tfmt, "func")) {
				isfp = true;
				// function pointer
			}
			if (isfp) {
				// consider function pointer as void * for printing
				r_strbuf_append (fmt_sb, "p");
				r_strbuf_appendf (vars_sb, "%s ", p);
			} else if (tfmt) {
				(void)r_str_replace_ch (type, ' ', '_', true);
				if (elements > 0) {
					r_strbuf_appendf (fmt_sb, "[%d]", elements);
				}
				if (isStruct) {
					r_strbuf_append (fmt_sb, "?");
					if (struct_name) {
						r_strbuf_appendf (vars_sb, "(%s)%s", struct_name, p);
					}
					r_strbuf_append (vars_sb, " ");
				} else if (isEnum) {
					r_strbuf_append (fmt_sb, "E");
					r_strbuf_appendf (vars_sb, "(%s)%s ", type + 5, p);
				} else {
					r_strbuf_append (fmt_sb, tfmt);
					r_strbuf_append (vars_sb, p);
					r_strbuf_append (vars_sb, " ");
				}
			} else {
#if 1
				R_LOG_WARN ("Cannot resolve type '%s' assuming pointer", var3);
				r_strbuf_append (fmt_sb, "p");
				r_strbuf_appendf (vars_sb, "%s ", p);
#else
				R_LOG_ERROR ("Cannot resolve type '%s'", var3);
#endif
			}
			free (type);
		}
		free (p);
	}
	free (fields);
	r_strbuf_append (fmt_sb, " ");
	char *vars_s = r_strbuf_drain (vars_sb);
	r_strbuf_append (fmt_sb, vars_s);
	free (vars_s);
	return r_strbuf_drain (fmt_sb);
}

R_API char *r_type_format(Sdb *TDB, const char *t) {
	char var[130], var2[132];
	const char *kind = sdb_const_get (TDB, t, NULL);
	if (!kind) {
		return NULL;
	}
	// only supports struct atm
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_get (TDB, var, NULL);
		if (fmt) {
			return strdup (fmt);
		}
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		return fmt_struct_union (TDB, var, false);
	}
	if (!strcmp (kind, "typedef")) {
		snprintf (var2, sizeof (var2), "typedef.%s", t);
		const char *type = sdb_const_get (TDB, var2, NULL);
		// only supports struct atm
		if (type && !strcmp (type, "struct")) {
			return fmt_struct_union (TDB, var, true);
		}
	}
	return NULL;
}

R_API void r_type_del(Sdb *TDB, const char *name) {
	r_strf_buffer (512);
	if (strstr (name, ".arg.")) {
		// ignore func argument definitions as they are not types
		return;
	}
	if (r_str_endswith (name, ".include")) {
		// ignore .include headers
		return;
	}
	const char *kind = sdb_const_get (TDB, name, 0);
	if (!kind) {
		return;
	}
	char *comma = strchr (kind, ',');
	if (comma) {
		R_LOG_WARN ("Unexpected comma in kind (%s) for (%s)", kind, name);
	}
	if (!strcmp (kind, "type")) {
		sdb_unset (TDB, r_strf ("type.%s", name), 0);
		sdb_unset (TDB, r_strf ("type.%s.size", name), 0);
		sdb_unset (TDB, r_strf ("type.%s.meta", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		char *elements_key = r_str_newf ("%s.%s", kind, name);
		int i, n = sdb_array_length (TDB, elements_key);
		for (i = 0; i < n; i++) {
			char *p = sdb_array_get (TDB, elements_key, i, NULL);
			sdb_unset (TDB, r_strf ("%s.%s", elements_key, p), 0);
			sdb_unset (TDB, r_strf ("%s.%s.meta", elements_key, p), 0);
			free (p);
		}
		sdb_unset (TDB, elements_key, 0);
		sdb_unset (TDB, name, 0);
		free (elements_key);
	} else if (!strcmp (kind, "func")) {
		int i, n = sdb_num_get (TDB, r_strf ("func.%s.args", name), 0);
		for (i = 0; i < n; i++) {
			sdb_unset (TDB, r_strf ("func.%s.arg.%d", name, i), 0);
		}
		sdb_unset (TDB, r_strf ("func.%s.ret", name), 0);
		sdb_unset (TDB, r_strf ("func.%s.cc", name), 0);
		sdb_unset (TDB, r_strf ("func.%s.noreturn", name), 0);
		sdb_unset (TDB, r_strf ("func.%s.args", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "enum")) {
		RList *list = r_type_get_enum (TDB, name);
		RTypeEnum *member;
		RListIter *iter;
		r_list_foreach (list, iter, member) {
			char *k = r_str_newf ("enum.%s.%s", name, member->name);
			sdb_unset (TDB, k, 0);
			free (k);
			k = r_str_newf ("enum.%s.%s", name, member->val);
			sdb_unset (TDB, k, 0);
			free (k);
		}
		sdb_unset (TDB, name, 0);
		r_list_free (list);
	} else if (!strcmp (kind, "typedef")) {
		char *buf = r_str_newf ("typedef.%s", name);
		sdb_unset (TDB, buf, 0);
		free (buf);
		sdb_unset (TDB, name, 0);
	} else {
		R_LOG_WARN ("Unrecognized type kind \"%s\" for (%s)", kind, name);
	}
}

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name) {
	const char *fcn = sdb_const_get (TDB, func_name, 0);
	return fcn && !strcmp (fcn, "func");
}

R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name) {
	r_strf_var (query, 64, "func.%s.ret", func_name);
	return sdb_const_get (TDB, query, 0);
}

R_API int r_type_func_args_count(Sdb *TDB, const char *R_NONNULL func_name) {
	r_strf_var (query, 64, "func.%s.args", func_name);
	return sdb_num_get (TDB, query, 0);
}

R_API R_OWN char *r_type_func_args_type(Sdb *TDB, const char *R_NONNULL func_name, int i) {
	char *query = r_str_newf ("func.%s.arg.%d", func_name, i);
	char *ret = sdb_get (TDB, query, 0);
	free (query);
	if (ret) {
		char *comma = strchr (ret, ',');
		if (comma) {
			*comma = 0;
			return ret;
		}
		return ret;
	}
	return NULL;
}

const char *const argnames[10] = {
	"arg0",
	"arg1",
	"arg2",
	"arg3",
	"arg4",
	"arg5",
	"arg6",
	"arg7",
	"arg8",
	"arg9",
};

R_API const char *r_type_func_args_name(Sdb *TDB, const char *R_NONNULL func_name, int i) {
	char *query = r_str_newf ("func.%s.arg.%d", func_name, i);
	const char *row = sdb_const_get (TDB, query, 0);
	free (query);
	if (row) {
		const char *ret = strchr (row, ',');
		if (ret) {
			return ret + 1;
		}
		if (i >= 0 && i < 10) {
			R_LOG_DEBUG ("Missing arg %d name for %s", i, func_name);
			return argnames[i];
		}
	}
	return NULL;
}

#define MIN_MATCH_LEN 4

static inline bool is_function(const char *name) {
	return name && !strcmp ("func", name);
}

static R_OWN char *type_func_try_guess(Sdb *TDB, char *R_NONNULL name) {
	if (strlen (name) < MIN_MATCH_LEN) {
		return NULL;
	}
	const char *res = sdb_const_get (TDB, name, NULL);
	if (is_function (res)) {
		return strdup (name);
	}
	return NULL;
}

static inline bool is_auto_named(char *func_name, size_t slen) {
	return slen > 4 && (r_str_startswith (func_name, "fcn.") || r_str_startswith (func_name, "loc."));
}

static inline bool has_r_prefixes(char *func_name, int offset, size_t slen) {
	return slen > 4 && (offset + 3 < slen) && func_name[offset + 3] == '.';
}

static char *strip_r_prefixes(char *func_name, size_t slen) {
	// strip r2 prefixes (sym, sym.imp, etc')
	int offset = 0;
	while (has_r_prefixes (func_name, offset, slen)) {
		offset += 4;
	}
	return func_name + offset;
}

static char *strip_common_prefixes_stdlib(char *func_name) {
	// strip common prefixes from standard lib functions
	if (r_str_startswith (func_name, "__isoc99_")) {
		func_name += 9;
	} else if (r_str_startswith (func_name, "__libc_") && !strstr (func_name, "_main")) {
		func_name += 7;
	} else if (r_str_startswith (func_name, "__GI_")) {
		func_name += 5;
	}
	return func_name;
}

static char *strip_dll_prefix(char *func_name) {
	char *tmp = strstr (func_name, "dll_");
	if (tmp) {
		return tmp + 3;
	}
	return func_name;
}

static void clean_function_name(char *func_name) {
	char *last = (char *)r_str_lchr (func_name, '_');
	if (!last || !r_str_isnumber (last + 1)) {
		return;
	}
	*last = '\0';
}

// TODO:
// - symbol names are long and noisy, some of them might not be matched due
//	 to additional information added around name
R_API R_OWN char *r_type_func_guess(Sdb *TDB, char *R_NONNULL func_name) {
	R_RETURN_VAL_IF_FAIL (TDB && func_name, false);
	char *str = func_name;
	char *result = NULL;

	size_t slen = strlen (str);
	if (slen < MIN_MATCH_LEN || is_auto_named (str, slen)) {
		return NULL;
	}

	str = strip_r_prefixes (str, slen);
	str = strip_common_prefixes_stdlib (str);
	str = strip_dll_prefix (str);

	if ( (result = type_func_try_guess (TDB, str))) {
		return result;
	}

	str = strdup (str);
	clean_function_name (str);

	if (*str == '_') {
		result = type_func_try_guess (TDB, str + 1);
	}

	free (str);
	return result;
}

R_API char *r_type_func_name(Sdb *types, const char *fname) {
	const char *str = fname;
	const char *name = fname;
	if (r_type_func_exist (types, fname)) {
		return strdup (fname);
	}
	while ( (str = strchr (str, '.'))) {
		str++;
		name = str;
	}
	if (r_type_func_exist (types, name)) {
		return strdup (name);
	}
	return r_type_func_guess (types, (char *)fname);
}
