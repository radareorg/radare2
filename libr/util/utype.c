/* radare - LGPL - Copyright 2013-2026 - pancake, oddcoder, sivaramaaa */

// R2R db/cmd/types

#include <r_util.h>

R_API bool r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val) {
	const char *kind = sdb_const_getf (TDB, NULL, "link.%08" PFMT64x, at);
	if (kind) {
		const char *p = sdb_const_get (TDB, kind, NULL);
		if (p) {
			char *v = r_str_newf ("%s.%s.%s", p, kind, field);
			ut64 off = 0;
			char *mtype = r_type_get_member (TDB, v, &off, NULL);
			free (mtype);
			free (v);
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
	if (type) {
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
	}
	return R_TYPE_INVALID;
}

// key is "struct.name.member" holding "type,offset,count"; split from the end since the type may itself contain commas
R_API R_OWNED char *r_type_get_member(Sdb *TDB, const char *key, ut64 *offset, int *count) {
	R_RETURN_VAL_IF_FAIL (TDB && key, NULL);
	if (offset) {
		*offset = 0;
	}
	if (count) {
		*count = 0;
	}
	char *val = sdb_get (TDB, key, NULL);
	if (R_STR_ISEMPTY (val)) {
		free (val);
		return NULL;
	}
	char *last = (char *)r_str_rchr (val, NULL, ',');
	if (!last) {
		return val;
	}
	*last = 0;
	char *mid = (char *)r_str_rchr (val, last - 1, ',');
	const char *offstr = last + 1;
	if (mid) {
		*mid = 0;
		offstr = mid + 1;
		if (count) {
			*count = (int)sdb_atoi (last + 1);
		}
	}
	if (offset) {
		*offset = sdb_atoi (offstr);
	}
	return val;
}

R_API RList *r_type_get_enum(Sdb *TDB, const char *name) {
	R_RETURN_VAL_IF_FAIL (TDB && name, NULL);
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
	const char *res = member
		? sdb_const_getf (TDB, NULL, "enum.%s.%s", name, member)
		: sdb_const_getf (TDB, NULL, "enum.%s.0x%" PFMT64x, name, val);
	if (!res) {
		res = sdb_const_getf (TDB, NULL, "enum.%s.%" PFMT64d, name, val);
	}
	return res? strdup (res): NULL;
}

R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val) {
	R_RETURN_VAL_IF_FAIL (TDB && name, NULL);
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
		const char *res = sdb_const_getf (TDB, NULL, "enum.%s.0x%x", name, n);
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

static const char *const type_qualifiers[] = {
	"const", "volatile", "restrict", "atomic", "_Atomic", NULL
};

static const char *type_skip_qualifiers(const char *R_NONNULL type) {
	int i;
	do {
		type = r_str_trim_head_ro (type);
		for (i = 0; type_qualifiers[i]; i++) {
			size_t qlen = strlen (type_qualifiers[i]);
			if (r_str_startswith (type, type_qualifiers[i]) && (!type[qlen] || IS_WHITESPACE (type[qlen]))) {
				type += qlen;
				break;
			}
		}
	} while (type_qualifiers[i]);
	return type;
}

static bool type_kind_is_aggregate(const char *R_NONNULL kind) {
	return !strcmp (kind, "struct") || !strcmp (kind, "union");
}

static const char *type_aggregate_prefixed(const char *R_NONNULL type, const char **R_NONNULL name) {
	const char *kind = r_str_startswith (type, "struct")? "struct": r_str_startswith (type, "union")? "union": NULL;
	if (kind) {
		size_t klen = strlen (kind);
		if (IS_WHITESPACE (type[klen])) {
			*name = r_str_trim_head_ro (type + klen);
			return R_STR_ISNOTEMPTY (*name)? kind: NULL;
		}
	}
	return NULL;
}

R_API ut64 r_type_get_bitsize(Sdb *R_NONNULL TDB, const char *R_NONNULL type) {
	R_RETURN_VAL_IF_FAIL (TDB && type, 0);
	/* Filter out qualifiers and the structure keyword if type looks like "struct mystruc" */
	const char *type_view = type_skip_qualifiers (type);
	const char *tmptype = type_view;
	const char *name = NULL;
	if (type_aggregate_prefixed (tmptype, &name)) {
		tmptype = name;
	}
	if ((strstr (type_view, "*(") || strstr (type_view, " *")) && strcmp (type_view, "char *")) {
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
		return sdb_num_getf (TDB, NULL, "type.%s.size", tmptype); // returns size in bits
	}
	if (!strcmp (t, "struct") || !strcmp (t, "union")) {
		const char *value = sdb_const_getf (TDB, NULL, "%s.%s", t, tmptype);
		char *members = value? strdup (value): NULL;
		char *next, *ptr = members;
		ut64 ret = 0;
		if (members) {
			do {
				char *name = sdb_anext (ptr, &next);
				if (!name) {
					break;
				}
				char *query = r_str_newf ("%s.%s.%s", t, tmptype, name);
				int elements = 0;
				char *subtype = r_type_get_member (TDB, query, NULL, &elements);
				free (query);
				if (!subtype) {
					break;
				}
				if (elements == 0) {
					elements = 1;
				}
				if (!strcmp (t, "struct")) {
					ret += r_type_get_bitsize (TDB, subtype) * elements;
				} else {
					ut64 sz = r_type_get_bitsize (TDB, subtype) * elements;
					ret = sz > ret ? sz : ret;
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

static const char *type_aggregate_kind(Sdb *R_NONNULL TDB, const char *R_NONNULL type, const char **R_NONNULL name) {
	const char *type_view = type_skip_qualifiers (type);
	if (strchr (type_view, '*')) {
		return NULL;
	}
	const char *kind = type_aggregate_prefixed (type_view, name);
	if (kind) {
		return kind;
	}
	const char *type_kind = sdb_const_get (TDB, type_view, NULL);
	if (type_kind && type_kind_is_aggregate (type_kind)) {
		*name = type_view;
		return type_kind;
	}
	return NULL;
}

static char *type_get_memb(Sdb *R_NONNULL TDB, const char *R_NONNULL kind, const char *R_NONNULL type, int offset, const char *R_NONNULL path) {
	int i, next_offset = 0;

	if (offset < 0) {
		return NULL;
	}
	const char *value = sdb_const_getf (TDB, NULL, "%s.%s", kind, type);
	char *members = value? strdup (value): NULL;
	if (!members) {
		return NULL;
	}
	char *res = NULL;
	bool is_struct = !strcmp (kind, "struct");
	int nargs = r_str_split (members, ',');
	for (i = 0; i < nargs; i++) {
		const char *name = r_str_word_get0 (members, i);
		const char *value = sdb_const_getf (TDB, NULL, "%s.%s.%s", kind, type, name);
		char *subtype = value? strdup (value): NULL;
		if (!subtype) {
			break;
		}
		int len = r_str_split (subtype, ',');
		if (len < 3) {
			free (subtype);
			break;
		}
		int cur_offset = r_num_math (NULL, r_str_word_get0 (subtype, len - 2));
		if (is_struct) {
			if (cur_offset > 0 && cur_offset < next_offset) {
				free (subtype);
				break;
			}
			if (!cur_offset) {
				cur_offset = next_offset;
			}
		}
		if (cur_offset == offset) {
			res = r_str_newf ("%s.%s", path, name);
			free (subtype);
			break;
		}
		int arrsz = r_num_math (NULL, r_str_word_get0 (subtype, len - 1));
		int fsize = (r_type_get_bitsize (TDB, subtype) * (arrsz ? arrsz : 1)) / 8;
		if (!fsize) {
			free (subtype);
			if (is_struct) {
				break;
			}
			continue;
		}
		int member_end = cur_offset + fsize;
		if (is_struct) {
			next_offset = member_end;
		}
		if (offset > cur_offset && offset < member_end) {
			const char *nested_type = r_str_word_get0 (subtype, 0);
			const char *nested_name = NULL;
			const char *nested_kind = type_aggregate_kind (TDB, nested_type, &nested_name);
			if (nested_kind) {
				char *nested_path = r_str_newf ("%s.%s", path, name);
				if (nested_path) {
					res = type_get_memb (TDB, nested_kind, nested_name, offset - cur_offset, nested_path);
					free (nested_path);
				}
				if (res) {
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

R_API char *r_type_get_struct_memb(Sdb *R_NONNULL TDB, const char *R_NONNULL type, int offset) {
	R_RETURN_VAL_IF_FAIL (TDB && type, NULL);
	return type_get_memb (TDB, "struct", type, offset, type);
}

// XXX this function is slow!
R_API RList *r_type_get_by_offset(Sdb *R_NONNULL TDB, ut64 offset) {
	R_RETURN_VAL_IF_FAIL (TDB, NULL);
	RList *offtypes = r_list_newf (free);
	if (offset > ST32_MAX) {
		return offtypes;
	}
	SdbList *ls = sdb_foreach_list (TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		const char *kk = sdbkv_key (kv);
		const char *vv = sdbkv_value (kv);
		if (type_kind_is_aggregate (vv)
			&& !r_str_startswith (kk, "struct.") && !r_str_startswith (kk, "union.")) {
			char *res = type_get_memb (TDB, vv, kk, offset, kk);
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
	const char *value = sdb_const_getf (db, NULL, "range.%" PFMT64x, base);
	char *r = value? strdup (value): NULL;
	if (r) {
		list = r_str_split_list (r, " ", -1);
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
	const char *value = sdb_const_getf (TDB, NULL, "link.%08" PFMT64x, addr);
	char *res = value? strdup (value): NULL;
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
			const char *link = sdb_const_getf (TDB, NULL, "link.%08" PFMT64x, laddr);
			char *k = link? strdup (link): NULL;
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

static int fmt_type_size(const char *tfmt, bool isfp, int elements) {
	int size = 0;
	if (isfp) {
		size = 8;
	} else if (tfmt) {
		if (!strcmp (tfmt, "d") || !strcmp (tfmt, "i") || !strcmp (tfmt, "x") || !strcmp (tfmt, "o") || !strcmp (tfmt, "f")) {
			size = 4;
		} else if (!strcmp (tfmt, "q") || !strcmp (tfmt, "F") || !strcmp (tfmt, "p") || !strcmp (tfmt, "z") || !strcmp (tfmt, "*z")) {
			size = 8;
		} else if (!strcmp (tfmt, "w")) {
			size = 2;
		} else if (!strcmp (tfmt, "b") || !strcmp (tfmt, "c") || !strcmp (tfmt, "C")) {
			size = 1;
		} else {
			size = 4;
		}
	} else {
		size = 8;
	}
	if (elements > 0) {
		size *= elements;
	}
	return size;
}

static char *fmt_struct_union(Sdb *TDB, char *var, bool is_typedef) {
	char *p = NULL, var2[132];
	size_t n;
	char *fields = r_str_newf ("%s.fields", var);
	char *nfields = (is_typedef) ? fields : var;
	RStrBuf *fmt_sb = r_strbuf_new ("");
	RStrBuf *vars_sb = r_strbuf_new ("");
	int current_offset = 0;
	for (n = 0; (p = sdb_array_get (TDB, nfields, n, NULL)); n++) {
		char *struct_name = NULL;
		const char *tfmt = NULL;
		bool isStruct = false;
		bool isEnum = false;
		bool isfp = false;
		bool isHidden = false;
		snprintf (var2, sizeof (var2), "%s.%s", var, p);
		ut64 member_offset = 0;
		int elements = 0;
		char *type = r_type_get_member (TDB, var2, &member_offset, &elements);
		int field_offset = (int)member_offset;
		if (field_offset > current_offset) {
			int pad = field_offset - current_offset;
			r_strbuf_appendf (fmt_sb, "[%d].", pad);
			current_offset = field_offset;
		}
		// Check for @visibility(hidden) attribute
		const char *visibility = sdb_const_getf (TDB, NULL, "%s.@.visibility", var2);
		if (visibility && !strcmp (visibility, "hidden")) {
			isHidden = true;
		}
		if (type) {
			char var3[128] = { 0 };
			char type_name[256] = { 0 };
			const char *enum_name = NULL;
			r_str_trim (type);
			r_str_ncpy (type_name, type_skip_qualifiers (type), sizeof (type_name));
			r_str_trim (type_name);
			char *arr = strchr (type_name, '[');
			if (arr) {
				char *arr_end = strchr (arr + 1, ']');
				if (arr_end) {
					bool pointee_array = false;
					char *close_paren = arr;
					while (close_paren > type_name && (close_paren[-1] == ' ' || close_paren[-1] == '\t')) {
						close_paren--;
					}
					if (close_paren > type_name && close_paren[-1] == ')') {
						char *open_paren = close_paren - 1;
						while (open_paren >= type_name && *open_paren != '(') {
							open_paren--;
						}
						if (open_paren >= type_name && memchr (open_paren, '*', (size_t)(close_paren - open_paren))) {
							pointee_array = true;
						}
					}
					*arr_end = 0;
					if (!pointee_array && elements <= 0) {
						int parsed_elems = atoi (arr + 1);
						if (parsed_elems > 0) {
							elements = parsed_elems;
						}
					}
					*arr = 0;
					r_str_trim (type_name);
				}
			}
			const char *base_type = type_name;
			if (r_str_startswith (base_type, "type.")) {
				base_type += 5;
			}
			// Handle general pointers except for char *
			if ((strstr (base_type, "*(") || strstr (base_type, " *")) && !r_str_startswith (base_type, "char *")) {
				isfp = true;
			} else {
				const char *aggregate_name = NULL;
				const char *type_kind = type_aggregate_kind (TDB, base_type, &aggregate_name);
				if (type_kind) {
					struct_name = (char *)aggregate_name;
					int name_len = (int)(sizeof (var3) - strlen (type_kind) - 2);
					snprintf (var3, sizeof (var3), "%s.%.*s", type_kind, name_len, aggregate_name);
					tfmt = sdb_const_get (TDB, var3, NULL);
					isStruct = true;
				} else {
					// special case for char[]. Use char* format type without *
					if (!strcmp (base_type, "char") && elements > 0) {
						tfmt = sdb_const_get (TDB, "type.char *", NULL);
						if (tfmt && *tfmt == '*') {
							tfmt++;
						}
					} else {
						if (r_str_startswith (base_type, "enum ")) {
							enum_name = base_type + 5;
							snprintf (var3, sizeof (var3), "%.*s",
									(int)(sizeof (var3) - 1), enum_name);
							isEnum = true;
						} else {
							snprintf (var3, sizeof (var3), "type.%.*s",
									(int)(sizeof (var3) - sizeof ("type.")), base_type);
						}
						tfmt = sdb_const_get (TDB, var3, NULL);
						if (!tfmt) {
							if (!strcmp (base_type, "int")) {
								tfmt = sdb_const_get (TDB, "type.int32_t", NULL);
								if (!tfmt) {
									tfmt = "d";
								}
							} else if (!strcmp (base_type, "short") || !strcmp (base_type, "short int")) {
								tfmt = sdb_const_get (TDB, "type.int16_t", NULL);
								if (!tfmt) {
									tfmt = "w";
								}
							} else if (!strcmp (base_type, "char")) {
								tfmt = sdb_const_get (TDB, "type.int8_t", NULL);
								if (!tfmt) {
									tfmt = "c";
								}
							} else if (!strcmp (base_type, "long long")
								|| !strcmp (base_type, "long long int")
								|| !strcmp (base_type, "int64_t")) {
								tfmt = sdb_const_get (TDB, "type.int64_t", NULL);
								if (!tfmt) {
									tfmt = "q";
								}
							}
						}
					}
				}
			}
			if (tfmt && !strcmp (tfmt, "func")) {
				isfp = true;
				// function pointer
			}
			if (isHidden) {
				// For hidden fields, skip the bytes without displaying
				// Use [N]. to skip N bytes (. skips 1 byte)
				int skip_bytes = 0;
				if (isfp) {
					// pointer size depends on platform, assume 8 for now
					skip_bytes = 8;
				} else if (tfmt) {
					// Get size from type format
					if (!strcmp (tfmt, "d") || !strcmp (tfmt, "i") || !strcmp (tfmt, "x") || !strcmp (tfmt, "o") || !strcmp (tfmt, "f")) {
						skip_bytes = 4;
					} else if (!strcmp (tfmt, "q") || !strcmp (tfmt, "F") || !strcmp (tfmt, "p")) {
						skip_bytes = 8;
					} else if (!strcmp (tfmt, "w")) {
						skip_bytes = 2;
					} else if (!strcmp (tfmt, "b") || !strcmp (tfmt, "c") || !strcmp (tfmt, "C") || !strcmp (tfmt, "z")) {
						skip_bytes = 1;
					} else {
						skip_bytes = 4; // default
					}
				} else {
					skip_bytes = 8; // assume pointer for unknown types
				}
				if (elements > 0) {
					skip_bytes *= elements;
				}
				if (skip_bytes > 0) {
					r_strbuf_appendf (fmt_sb, "[%d].", skip_bytes);
					current_offset += skip_bytes;
				}
			} else if (isfp) {
				r_strbuf_append (fmt_sb, "p");
				r_strbuf_appendf (vars_sb, "%s ", p);
				current_offset += fmt_type_size (NULL, true, elements);
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
						r_strbuf_appendf (vars_sb, "(%s)%s ", enum_name ? enum_name : base_type, p);
					} else {
						r_strbuf_append (fmt_sb, tfmt);
						r_strbuf_append (vars_sb, p);
					r_strbuf_append (vars_sb, " ");
				}
				current_offset += fmt_type_size (tfmt, false, elements);
			} else {
#if 1
				R_LOG_WARN ("Cannot resolve type '%s' assuming pointer", var3);
				r_strbuf_append (fmt_sb, "p");
				r_strbuf_appendf (vars_sb, "%s ", p);
				current_offset += fmt_type_size (NULL, true, elements);
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
	const char *kind = sdb_const_get (TDB, t, NULL);
	if (!kind) {
		return NULL;
	}
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_getf (TDB, NULL, "type.%s", t);
		return fmt? strdup (fmt): NULL;
	}
	char var[130];
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "struct")) {
		return fmt_struct_union (TDB, var, false);
	} else if (!strcmp (kind, "union")) {
		char *fmt = fmt_struct_union (TDB, var, false);
		if (fmt) {
			char *res = r_str_newf ("0%s", fmt);
			free (fmt);
			return res;
		}
		return NULL;
	}
	if (!strcmp (kind, "typedef")) {
		const char *type = sdb_const_getf (TDB, NULL, "typedef.%s", t);
		if (type && !strcmp (type, "struct")) {
			return fmt_struct_union (TDB, var, true);
		}
		if (type && !strcmp (type, "union")) {
			char *fmt = fmt_struct_union (TDB, var, true);
			if (fmt) {
				char *res = r_str_newf ("0%s", fmt);
				free (fmt);
				return res;
			}
			return NULL;
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
	const char *comma = strchr (kind, ',');
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
		int i, n = sdb_num_getf (TDB, NULL, "func.%s.args", name);
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

// Strip leading __ prefix for type database lookup
// This allows __strcpy_chk to match strcpy_chk in the database
static inline const char *trim_lodashes(const char *name) {
	while (r_str_startswith (name, "__")) {
		name += 2;
	}
	return name;
}

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name) {
	const char *fcn = sdb_const_get (TDB, trim_lodashes (func_name), 0);
	return fcn && !strcmp (fcn, "func");
}

R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name) {
	return sdb_const_getf (TDB, NULL, "func.%s.ret", trim_lodashes (func_name));
}

R_API int r_type_func_args_count(Sdb *TDB, const char *R_NONNULL func_name) {
	return sdb_num_getf (TDB, NULL, "func.%s.args", trim_lodashes (func_name));
}

R_API R_OWNED char *r_type_func_args_type(Sdb *TDB, const char *R_NONNULL func_name, int i) {
	const char *value = sdb_const_getf (TDB, NULL, "func.%s.arg.%d", trim_lodashes (func_name), i);
	char *ret = value? strdup (value): NULL;
	if (ret) {
		char *comma = strchr (ret, ',');
		if (comma) {
			*comma = 0;
		}
	}
	return ret;
}

static const char *const argnames[10] = {
	"arg0", "arg1", "arg2", "arg3", "arg4",
	"arg5", "arg6", "arg7", "arg8", "arg9",
};

R_API const char *r_type_func_args_name(Sdb *TDB, const char *R_NONNULL func_name, int i) {
	const char *row = sdb_const_getf (TDB, NULL, "func.%s.arg.%d", trim_lodashes (func_name), i);
	if (row) {
		const char *ret = strchr (row, ',');
		if (ret) {
			return ret + 1;
		}
	}
	return (i >= 0 && i < 10)? argnames[i]: "arg";
}

#define MIN_MATCH_LEN 4

static inline bool is_function(const char *name) {
	return name && !strcmp ("func", name);
}

static R_OWNED char *type_func_try_guess(Sdb *TDB, const char *name) {
	if (strlen (name) < MIN_MATCH_LEN) {
		return NULL;
	}
	const char *res = sdb_const_get (TDB, name, NULL);
	if (is_function (res)) {
		return strdup (name);
	}
	// strip leading underscores (e.g., __libc_start_main -> libc_start_main)
	if (r_str_startswith (name, "__")) {
		const char *stripped = name;
		while (*stripped == '_') {
			stripped++;
		}
		res = sdb_const_get (TDB, stripped, NULL);
		if (is_function (res)) {
			return strdup (stripped);
		}
	}
	return NULL;
}

static inline bool is_auto_named(const char *func_name, size_t slen) {
	return slen > 4 && (r_str_startswith (func_name, "fcn.") || r_str_startswith (func_name, "loc."));
}

static inline bool has_r_prefixes(const char *func_name, int offset, size_t slen) {
	return slen > 4 && (offset + 3 < slen) && func_name[offset + 3] == '.';
}

static const char *strip_r_prefixes(const char *func_name, size_t slen) {
	// strip r2 prefixes (sym, sym.imp, etc')
	int offset = 0;
	while (has_r_prefixes (func_name, offset, slen)) {
		offset += 4;
	}
	return func_name + offset;
}

static const char *strip_common_prefixes_stdlib(const char *func_name) {
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

static const char *strip_dll_prefix(const char *func_name, bool *stripped) {
	const char *tmp = strstr (func_name, "dll_");
	if (tmp) {
		if (stripped) {
			*stripped = true;
		}
		return tmp + 4;
	}
	if (stripped) {
		*stripped = false;
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
R_API R_OWNED char *r_type_func_guess(Sdb *TDB, const char *R_NONNULL func_name) {
	R_RETURN_VAL_IF_FAIL (TDB && func_name, NULL);
	const char *str = func_name;
	char *result = NULL;

	size_t slen = strlen (str);
	if (slen < MIN_MATCH_LEN || is_auto_named (str, slen)) {
		return NULL;
	}

	str = strip_r_prefixes (str, slen);
	str = strip_common_prefixes_stdlib (str);
	bool dll_stripped = false;
	str = strip_dll_prefix (str, &dll_stripped);

	if ((result = type_func_try_guess (TDB, str))) {
		return result;
	}

	// afs stores prototypes under the prefixed name, retry it unstripped
	if (str != func_name && (result = type_func_try_guess (TDB, func_name))) {
		return result;
	}

	char *str_copy = strdup (str);
	clean_function_name (str_copy);

	// If we stripped dll_ prefix, try matching the cleaned name directly
	if (dll_stripped) {
		result = type_func_try_guess (TDB, str_copy);
	}
	if (!result && *str_copy == '_') {
		// Also try without leading underscore
		result = type_func_try_guess (TDB, str_copy + 1);
	}

	// auto-detect JNI native functions and callbacks
	if (!result && (r_str_startswith (str, "Java_") || r_str_startswith (str, "JNI_"))) {
		result = type_func_try_guess (TDB, "jni_native");
	}
	free (str_copy);
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
	return r_type_func_guess (types, fname);
}
