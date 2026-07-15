/* radare - LGPL - Copyright 2019-2023 - pancake, oddcoder, Anton Kochkov */

#include <r_anal.h>
#include <r_anal_priv.h>
#include <stdarg.h>
#include <string.h>
#include <sdb/sdb.h>

#define KSZ 256

// XXX this function needs to be rewritten
static char *is_type(char *type) {
	char *name = NULL;
	if ((name = strstr (type, "=type")) ||
			(name = strstr (type, "=struct")) ||
			(name = strstr (type, "=union")) ||
			(name = strstr (type, "=enum")) ||
			(name = strstr (type, "=typedef")) ||
			(name = strstr (type, "=func"))) {
		return name;
	}
	return NULL;
}

static char *get_type_data(Sdb *sdb_types, const char *type, const char *sname) {
	const char *value = sdb_const_getf (sdb_types, NULL, "%s.%s", type, sname);
	return value? strdup (value): NULL;
}

static void sdb_concat_by_path(Sdb *s, const char *path) {
	R_RETURN_IF_FAIL (s && path);
	Sdb *db = sdb_new (0, path, 0);
	if (db) {
		sdb_merge (s, db);
		sdb_close (db);
		sdb_free (db);
	}
}

static void load_types_from(RAnal *anal, const char *fmt, ...) {
	R_RETURN_IF_FAIL (anal && fmt);
	va_list ap;
	va_start (ap, fmt);
	char *s = r_str_newvf (fmt, ap);
	va_end (ap);
	if (!s) {
		return;
	}
	SdbGperf *gp = r_anal_get_gperf_types (s);
	if (gp) {
#if HAVE_GPERF
		Sdb *gd = sdb_new0 ();
		if (gd) {
			sdb_open_gperf (gd, gp);
			sdb_merge (anal->sdb_types, gd);
			sdb_close (gd);
			sdb_free (gd);
		}
#endif
	} else {
		const char *dir_prefix = R_ANAL_PRIV (anal)->dir_prefix;
		if (R_STR_ISNOTEMPTY (dir_prefix)) {
			char *dbpath = r_str_newf ("%s/%s/%s.sdb", dir_prefix, R2_SDB_FCNSIGN, s);
			if (dbpath && r_file_exists (dbpath)) {
				sdb_concat_by_path (anal->sdb_types, dbpath);
			}
			free (dbpath);
		}
	}
	free (s);
}

R_IPI void r_anal_types_ensure_loaded(RAnal *anal) {
	R_RETURN_IF_FAIL (anal && anal->config && anal->sdb_types);
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	const char *arch = anal->config->arch;
	const int bits = anal->config->bits;
	const char *os = anal->config->os;
	const bool merge = !priv->types_loaded_bits && !sdb_isempty (anal->sdb_types);

	if (!priv->types_dirty && priv->types_loaded_bits == bits) {
		return;
	}
	if (!arch) {
		arch = "";
	}
	if (!os) {
		os = "";
	}
	if (!merge) {
		sdb_reset (anal->sdb_types);
	}
	load_types_from (anal, "types");
	load_types_from (anal, "types-%s", arch);
	load_types_from (anal, "types-%s", os);
	if (!strcmp (os, "ios") || !strcmp (os, "macos")) {
		load_types_from (anal, "types-darwin");
	}
	if (!strcmp (os, "android")) {
		load_types_from (anal, "types-jni");
	}
	load_types_from (anal, "types-%d", bits);
	load_types_from (anal, "types-%s-%d", os, bits);
	load_types_from (anal, "types-%s-%d", arch, bits);
	load_types_from (anal, "types-%s-%s", arch, os);
	load_types_from (anal, "types-%s-%s-%d", arch, os, bits);
	priv->types_dirty = false;
	priv->types_loaded_bits = bits;
}

R_API void r_anal_types_reload(RAnal *anal, const char *dir_prefix, const char *os, const char *subsystem) {
	R_RETURN_IF_FAIL (anal && anal->config && anal->sdb_types);
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	if (R_STR_ISNOTEMPTY (dir_prefix)) {
		free (priv->dir_prefix);
		priv->dir_prefix = strdup (dir_prefix);
	}
	const char *arch = anal->config->arch;
	const int bits = anal->config->bits;
	// Check if types need to be reloaded due to bits change
	if (!priv->types_dirty && priv->types_loaded_bits == bits) {
		return;
	}
	if (!arch) {
		arch = "";
	}
	if (!os) {
		os = anal->config->os;
	}
	if (!os) {
		os = "";
	}
	sdb_reset (anal->sdb_types);
	load_types_from (anal, "types");
	load_types_from (anal, "types-%s", arch);
	load_types_from (anal, "types-%s", os);
	if (!strcmp (os, "ios") || !strcmp (os, "macos")) {
		load_types_from (anal, "types-darwin");
	}
	if (subsystem && !strcmp (subsystem, "xnu")) {
		load_types_from (anal, "types-iokit");
	}
	if (!strcmp (os, "android")) {
		load_types_from (anal, "types-jni");
	}
	load_types_from (anal, "types-%d", bits);
	load_types_from (anal, "types-%s-%d", os, bits);
	load_types_from (anal, "types-%s-%d", arch, bits);
	load_types_from (anal, "types-%s-%s", arch, os);
	load_types_from (anal, "types-%s-%s-%d", arch, os, bits);
	priv->types_dirty = false;
	priv->types_loaded_bits = bits;
}

R_API void r_anal_types_load_sdb(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	load_types_from (anal, "%s", name);
}

R_API void r_anal_remove_parsed_type(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	Sdb *TDB = anal->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get (TDB, name, 0);
	if (!type) {
		return;
	}

	// Create a subkey before the call to r_type_del (which leaves the type string invalid)
	char *subkey = r_str_newf ("%s.%s.", type, name);
	r_type_del (TDB, name);

	// TODO: This loop should be optimized
	SdbList *l = sdb_foreach_list (TDB, true);
	size_t subkey_len = strlen (subkey);
	ls_foreach (l, iter, kv) {
		const char *key = sdbkv_key (kv);
		if (!strncmp (key, subkey, subkey_len)) {
			r_type_del (TDB, key);
		}
	}
	ls_free (l);
	free (subkey);
}

// RENAME TO r_anal_types_save(); // parses the string and imports the types
R_API void r_anal_save_parsed_type(RAnal *anal, const char *parsed) {
	R_RETURN_IF_FAIL (anal && parsed);
	r_anal_types_ensure_loaded (anal);

	// First, if any parsed types exist, let's remove them.
	char *type = strdup (parsed);
	if (type) {
		char *cur = type;
		while (1) {
			cur = is_type (cur);
			if (!cur) {
				break;
			}
			char *name = cur++;
			*name = 0;
			while (name > type && *(name - 1) != '\n') {
				name--;
			}
			r_anal_remove_parsed_type (anal, name);
		}
		free (type);
	}

	// Now add the type to sdb.
	sdb_query_lines (anal->sdb_types, parsed);
}

R_API bool r_anal_import_c_decls(RAnal *anal, const char *decls, char **errmsg) {
	R_RETURN_VAL_IF_FAIL (anal && decls, false);
	if (errmsg) {
		*errmsg = NULL;
	}
	char *error_msg = NULL;
	char *out = r_anal_cparse (anal, decls, &error_msg);
	if (out) {
		r_anal_save_parsed_type (anal, out);
	}
	if (errmsg) {
		*errmsg = error_msg;
	} else {
		free (error_msg);
	}
	bool success = out != NULL;
	free (out);
	return success;
}

static ut64 typecmp_val(const void *a) {
	return r_str_hash64 (a);
}

R_API RList *r_anal_types_from_fcn(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	RList *type_used = r_list_new ();
	if (!type_used) {
		return NULL;
	}
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		r_list_append (type_used, var->type);
	}
	r_list_uniq_inplace (type_used, typecmp_val);
	return type_used;
}

static RAnalBaseType *get_enum_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}

	char *members = get_type_data (anal->sdb_types, "enum", sname);
	if (!members) {
		goto error;
	}

	RVecAnalEnumCase *cases = &base_type->enum_data.cases;
	if (!RVecAnalEnumCase_reserve (cases, (size_t)sdb_alen (members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach (cur, members) {
		const char *value = sdb_const_getf (anal->sdb_types, NULL, "enum.%s.%s", sname, cur);

		if (!value) { // if nothing is found, ret NULL
			goto error;
		}

		RAnalEnumCase cas = { .name = strdup (cur), .val = strtol (value, NULL, 16) };

		RAnalEnumCase *element = RVecAnalEnumCase_emplace_back (cases);
		*element = cas;

		sdb_aforeach_next (cur);
	}
	free (members);

	return base_type;

error:
	free (members);
	r_anal_base_type_free (base_type);
	return NULL;
}

// values is "type,offset,count"; split from the end since the type may itself contain commas
static void split_member_csv(char *values, const char **offset, const char **count) {
	*offset = NULL;
	*count = NULL;
	char *last = (char *)r_str_rchr (values, NULL, ',');
	if (!last) {
		return;
	}
	*last = 0;
	char *mid = (char *)r_str_rchr (values, last - 1, ',');
	if (mid) {
		*mid = 0;
		*offset = mid + 1;
		*count = last + 1;
	} else {
		*offset = last + 1;
	}
}

static RAnalBaseType *get_composite_type(RAnal *anal, const char *sname, RAnalBaseTypeKind kind) {
	R_RETURN_VAL_IF_FAIL (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (kind);
	if (!base_type) {
		return NULL;
	}

	const char *kindstr = (kind == R_ANAL_BASE_TYPE_KIND_UNION)? "union": "struct";
	char *sdb_members = get_type_data (anal->sdb_types, kindstr, sname);
	if (!sdb_members) {
		goto error;
	}

	RVecAnalTypeMember *members = r_anal_base_type_members (base_type);
	if (!RVecAnalTypeMember_reserve (members, (size_t)sdb_alen (sdb_members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach (cur, sdb_members) {
		const char *value = sdb_const_getf (anal->sdb_types, NULL, "%s.%s.%s", kindstr, sname, cur);
		char *values = value? strdup (value): NULL;

		if (!values) {
			goto error;
		}
		const char *offset = NULL;
		const char *count = NULL;
		split_member_csv (values, &offset, &count);
		RAnalTypeMember memb = {
			.name = strdup (cur),
			.type = strdup (values),
			.offset = offset? strtoul (offset, NULL, 10): 0,
			.count = R_STR_ISNOTEMPTY (count)? strtoul (count, NULL, 10): 0
		};
		free (values);

		RAnalTypeMember *element = RVecAnalTypeMember_emplace_back (members);
		*element = memb;

		sdb_aforeach_next (cur);
	}
	free (sdb_members);

	return base_type;

error:
	r_anal_base_type_free (base_type);
	free (sdb_members);
	return NULL;
}

static RAnalBaseType *get_typedef_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (sname), NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}

	base_type->type = get_type_data (anal->sdb_types, "typedef", sname);
	if (!base_type->type) {
		goto error;
	}
	return base_type;

error:
	r_anal_base_type_free (base_type);
	return NULL;
}

static RAnalBaseType *get_atomic_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (sname), NULL);
	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (base_type) {
		base_type->type = get_type_data (anal->sdb_types, "type", sname);
		if (base_type->type) {
			base_type->size = sdb_num_getf (anal->sdb_types, NULL, "type.%s.size", sname);
			return base_type;
		}
		r_anal_base_type_free (base_type);
	}
	return NULL;
}

// returns NULL if name is not found or any failure happened
R_API RAnalBaseType *r_anal_get_base_type(RAnal *anal, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal && name, NULL);

	char *sname = r_str_sanitize_sdb_key (name);
	const char *type = sdb_const_get (anal->sdb_types, sname, NULL);
	if (!type) {
		free (sname);
		return NULL;
	}

	RAnalBaseType *base_type = NULL;
	if (!strcmp (type, "struct")) {
		base_type = get_composite_type (anal, sname, R_ANAL_BASE_TYPE_KIND_STRUCT);
	} else if (!strcmp (type, "enum")) {
		base_type = get_enum_type (anal, sname);
	} else if (!strcmp (type, "union")) {
		base_type = get_composite_type (anal, sname, R_ANAL_BASE_TYPE_KIND_UNION);
	} else if (!strcmp (type, "typedef")) {
		base_type = get_typedef_type (anal, sname);
	} else if (!strcmp (type, "type")) {
		base_type = get_atomic_type (anal, sname);
	}

	if (base_type) {
		base_type->name = sname;
	} else {
		free (sname);
	}

	return base_type;
}

R_API RList *r_anal_types_baselist(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RList *types = r_list_newf ((RListFree)r_anal_base_type_free);
	if (!types) {
		return NULL;
	}

	SdbList *keys = sdb_foreach_list (anal->sdb_types, true);
	if (!keys) {
		return types;
	}

	SdbKv *kv;
	SdbListIter *iter;
	ls_foreach (keys, iter, kv) {
		const char *name = sdbkv_key (kv);
		const char *kind = sdbkv_value (kv);
		if (R_STR_ISEMPTY (name) || R_STR_ISEMPTY (kind)) {
			continue;
		}
		if (strchr (name, '.')) {
			continue;
		}
		if (strcmp (kind, "struct") && strcmp (kind, "union")
			&& strcmp (kind, "enum") && strcmp (kind, "typedef")
			&& strcmp (kind, "type")) {
			continue;
		}
		RAnalBaseType *base_type = r_anal_get_base_type (anal, name);
		if (base_type) {
			r_list_append (types, base_type);
		}
	}
	ls_free (keys);
	return types;
}

// canonical serialization of a struct/union member value: "type,offset,arraycount"
static char *member_value_kv(const char *type, size_t offset, size_t count) {
	return r_str_newf ("%s,%u,%u", type, (unsigned int)offset, (unsigned int)count);
}

/* Serialize a struct or union base type into the sdb-types text lines that
 * get_struct_type/get_union_type read back:
 *   name=struct
 *   struct.name.member=type,offset,arraycount
 *   struct.name=member1,member2
 * The returned string can be applied with sdb_query_lines() and is the
 * canonical schema shared with the C parser (c2/kv.c). */
R_API char *r_anal_base_type_to_kv(const RAnalBaseType *type) {
	R_RETURN_VAL_IF_FAIL (type && type->name, NULL);
	const char *kind;
	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
		kind = "struct";
		break;
	case R_ANAL_BASE_TYPE_KIND_UNION:
		kind = "union";
		break;
	default:
		// enum/typedef/atomic serialization is not unified through here yet
		return NULL;
	}
	char *sname = r_str_sanitize_sdb_key (type->name);
	RStrBuf *sb = r_strbuf_new ("");
	RStrBuf *list = r_strbuf_new ("");
	r_strbuf_appendf (sb, "%s=%s\n", sname, kind);
	int i = 0;
	RAnalTypeMember *member;
	R_VEC_FOREACH (r_anal_base_type_members (type), member) {
		char *mname = r_str_sanitize_sdb_key (member->name);
		char *value = member_value_kv (member->type, member->offset, member->count);
		r_strbuf_appendf (sb, "%s.%s.%s=%s\n", kind, sname, mname, value);
		r_strbuf_appendf (list, "%s%s", i++? ",": "", mname);
		free (value);
		free (mname);
	}
	char *lists = r_strbuf_drain (list);
	r_strbuf_appendf (sb, "%s.%s=%s\n", kind, sname, lists);
	free (lists);
	free (sname);
	return r_strbuf_drain (sb);
}

static void save_composite(const RAnal *anal, const RAnalBaseType *type) {
	const char *kind = (type->kind == R_ANAL_BASE_TYPE_KIND_UNION)? "union": "struct";
	/*
		C:
		struct name {type param1; type param2; type paramN;};
		Sdb:
		name=struct
		struct.name=param1,param2,paramN
		struct.name.param1=type,0,0
		struct.name.param2=type,4,0
		struct.name.paramN=type,8,0
	*/
	RVecAnalTypeMember *members = r_anal_base_type_members (type);
	Sdb *db = anal->sdb_types;
	char *sname = r_str_sanitize_sdb_key (type->name);
	char *key = r_str_newf ("%s.%s", kind, sname);
	char *old = sdb_get (db, key, 0);
	if (old && RVecAnalTypeMember_empty (members)) {
		// a forward declaration must not clobber the full definition
		R_LOG_DEBUG ("Ignoring overwrite of type '%s' with an empty declaration", key);
		free (old);
		free (key);
		free (sname);
		return;
	}
	if (old) {
		// drop the members of the replaced definition before writing the new ones
		char *p;
		sdb_aforeach (p, old) {
			r_strf_var (mk, KSZ, "%s.%s.%s", kind, sname, p);
			sdb_unset (db, mk, 0);
			sdb_aforeach_next (p);
		}
		free (old);
	}
	// name=struct
	sdb_set (db, sname, kind, 0);

	RStrBuf *arglist = r_strbuf_new ("");

	int i = 0;
	RAnalTypeMember *member;
	R_VEC_FOREACH (members, member) {
		// struct.name.param=type,offset,arraycount
		char *member_sname = r_str_sanitize_sdb_key (member->name);
		r_strf_var (k, KSZ, "%s.%s.%s", kind, sname, member_sname);
		sdb_set_owned (db, k,
			member_value_kv (member->type, member->offset, member->count), 0);
		free (member_sname);

		r_strbuf_appendf (arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// struct.name=param1,param2,paramN
	sdb_set_owned (db, key, r_strbuf_drain (arglist), 0);

	free (key);
	free (sname);
}

static void save_enum(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name);
	R_RETURN_IF_FAIL (type->kind == R_ANAL_BASE_TYPE_KIND_ENUM);
	/*
		C:
			enum name {case1 = 1, case2 = 2, caseN = 3};
		Sdb:
		name=enum
		enum.name=arg1,arg2,argN
		enum.MyEnum.0x1=arg1
		enum.MyEnum.0x3=arg2
		enum.MyEnum.0x63=argN
		enum.MyEnum.arg1=0x1
		enum.MyEnum.arg2=0x63
		enum.MyEnum.argN=0x3
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "enum", 0);

	RStrBuf *arglist = r_strbuf_new ("");
	int i = 0;
	RAnalEnumCase *cas;
	R_VEC_FOREACH (&type->enum_data.cases, cas) {
		// enum.name.arg1=type,offset,???
		char *case_sname = r_str_sanitize_sdb_key (cas->name);
		r_strf_var (param_val, KSZ, "0x%" PFMT32x, cas->val);
		sdb_setf (anal->sdb_types, param_val, 0, "enum.%s.%s", sname, case_sname);
		sdb_setf (anal->sdb_types, case_sname, 0, "enum.%s.0x%" PFMT32x, sname, cas->val);
		free (case_sname);
		r_strbuf_appendf (arglist, (i++ == 0) ? "%s" : ",%s", cas->name);
	}
	// enum.name=arg1,arg2,argN
	char *key = r_str_newf ("enum.%s", sname);
	sdb_set_owned (anal->sdb_types, key, r_strbuf_drain (arglist), 0);
	free (key);

	free (sname);
}

static void save_atomic_type(const RAnal *anal, const RAnalBaseType *type) {
	r_strf_buffer (KSZ);
	R_RETURN_IF_FAIL (anal && type && type->name);
	R_RETURN_IF_FAIL (type->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "type", 0);
#if 0
	sdb_num_set (anal->sdb_types, r_strf ("type.%s.size", sname), type->size, 0);
#else
	char *ns = r_str_newf ("%" PFMT64u, (ut64)type->size);
	sdb_set_owned (anal->sdb_types, r_strf ("type.%s.size", sname), ns, 0);
#endif
	sdb_setf (anal->sdb_types, type->type, 0, "type.%s", sname);
	free (sname);
}

static void save_typedef(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name && type->kind == R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		// type.byte=typedef
		byte=typedef
		typedef.byte=char
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "typedef", 0);
	sdb_setf (anal->sdb_types, type->type, 0, "typedef.%s", sname);
#if 0
	sdb_set (anal->sdb_types, r_strf ("type.%s", sname), "typedef", 0);
#endif
	free (sname);
}

R_API void r_anal_base_type_free(RAnalBaseType *type) {
	R_RETURN_IF_FAIL (type);
	free (type->name);
	free (type->type);

	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
	case R_ANAL_BASE_TYPE_KIND_UNION:
		RVecAnalTypeMember_fini (r_anal_base_type_members (type));
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		RVecAnalEnumCase_fini (&type->enum_data.cases);
		break;
	case R_ANAL_BASE_TYPE_KIND_TYPEDEF:
	case R_ANAL_BASE_TYPE_KIND_ATOMIC:
		break;
	default:
		break;
	}
	free (type);
}

R_API RAnalBaseType *r_anal_base_type_new(RAnalBaseTypeKind kind) {
	RAnalBaseType *type = R_NEW0 (RAnalBaseType);
	if (type) {
		type->kind = kind;
		switch (type->kind) {
		case R_ANAL_BASE_TYPE_KIND_STRUCT:
		case R_ANAL_BASE_TYPE_KIND_UNION:
			RVecAnalTypeMember_init (r_anal_base_type_members (type));
			break;
		case R_ANAL_BASE_TYPE_KIND_ENUM:
			RVecAnalEnumCase_init (&type->enum_data.cases);
			break;
		default:
			break;
		}
	}
	return type;
}

/**
 * @brief Saves RAnalBaseType into the SDB
 *
 * @param anal
 * @param type RAnalBaseType to save
 * @param name Name of the type
 */
R_API void r_anal_save_base_type(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name);

	// TODO, solve collisions, if there are 2 types with the same name and kind

	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
	case R_ANAL_BASE_TYPE_KIND_UNION:
		save_composite (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		save_enum (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_TYPEDEF:
		save_typedef (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_ATOMIC:
		save_atomic_type (anal, type);
		break;
	default:
		break;
	}
}
