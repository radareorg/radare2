/* radare - LGPL - Copyright 2019-2023 - pancake, oddcoder, Anton Kochkov */

#include <r_anal.h>
#include <string.h>
#include <sdb/sdb.h>
#include "base_types.h"

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
	char *key = r_str_newf ("%s.%s", type, sname);
	if (!key) {
		return NULL;
	}
	char *members = sdb_get (sdb_types, key, NULL);
	free (key);
	return members;
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

static ut64 typecmp_val(const void *a) {
	return r_str_hash64 (a);
}

R_API RList *r_anal_types_from_fcn(RAnal *anal, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalVar *var;
	RList *list = r_anal_var_all_list (anal, fcn);
	RList *type_used = r_list_new ();
	r_list_foreach (list, iter, var) {
		r_list_append (type_used, var->type);
	}
	r_list_uniq_inplace (type_used, typecmp_val);
	return type_used;
}

R_IPI void enum_type_case_free(void *e, void *user) {
	(void)user;
	RAnalEnumCase *cas = e;
	free (cas->name);
}

R_IPI void struct_type_member_free(void *e, void *user) {
	(void)user;
	RAnalStructMember *member = e;
	free (member->name);
	free (member->type);
}

R_IPI void union_type_member_free(void *e, void *user) {
	(void)user;
	RAnalUnionMember *member = e;
	free (member->name);
	free (member->type);
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
		char *val_key = r_str_newf ("enum.%s.%s", sname, cur);
		if (!val_key) {
			goto error;
		}
		const char *value = sdb_const_get (anal->sdb_types, val_key, NULL);
		free (val_key);

		if (!value) { // if nothing is found, ret NULL
			goto error;
		}

		RAnalEnumCase cas = { .name = strdup (cur), .val = strtol (value, NULL, 16) };

		RAnalEnumCase *element = RVecAnalEnumCase_emplace_back (cases);
		if (!element) {
			goto error;
		}
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

static RAnalBaseType *get_struct_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data (anal->sdb_types, "struct", sname);
	if (!sdb_members) {
		goto error;
	}

	RVecAnalStructMember *members = &base_type->struct_data.members;
	if (!RVecAnalStructMember_reserve (members, (size_t)sdb_alen (sdb_members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach (cur, sdb_members) {
		char *type_key = r_str_newf ("struct.%s.%s", sname, cur);
		if (!type_key) {
			goto error;
		}
		char *values = sdb_get (anal->sdb_types, type_key, NULL);
		free (type_key);

		if (!values) {
			goto error;
		}
		char *offset = NULL;
		char *type = sdb_anext (values, &offset);
		if (!offset) { // offset is missing, malformed state
			free (values);
			goto error;
		}
		offset = sdb_anext (offset, NULL);
		RAnalStructMember cas = {
			.name = strdup (cur),
			.type = strdup (type),
			.offset = strtol (offset, NULL, 10)
		};

		free (values);

		RAnalStructMember *element = RVecAnalStructMember_emplace_back (members);
		if (!element) {
			goto error;
		}
		*element = cas;

		sdb_aforeach_next (cur);
	}
	free (sdb_members);

	return base_type;

error:
	r_anal_base_type_free (base_type);
	free (sdb_members);
	return NULL;
}

static RAnalBaseType *get_union_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data (anal->sdb_types, "union", sname);
	if (!sdb_members) {
		goto error;
	}

	RVecAnalUnionMember *members = &base_type->union_data.members;
	if (!RVecAnalUnionMember_reserve (members, (size_t)sdb_alen (sdb_members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach (cur, sdb_members) {
		char *type_key = r_str_newf ("union.%s.%s", sname, cur);
		if (!type_key) {
			goto error;
		}
		char *values = sdb_get (anal->sdb_types, type_key, NULL);
		free (type_key);

		if (!values) {
			goto error;
		}
		char *value = sdb_anext (values, NULL);
		RAnalUnionMember cas = { .name = strdup (cur), .type = strdup (value) };
		free (values);

		RAnalUnionMember *element = RVecAnalUnionMember_emplace_back (members);
		if (!element) {
			goto error;
		}
		*element = cas;

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
	r_strf_buffer (KSZ);
	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (base_type) {
		base_type->type = get_type_data (anal->sdb_types, "type", sname);
		if (base_type->type) {
			base_type->size = sdb_num_get (anal->sdb_types, r_strf ("type.%s.size", sname), 0);
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
		base_type = get_struct_type (anal, sname);
	} else if (!strcmp (type, "enum")) {
		base_type = get_enum_type (anal, sname);
	} else if (!strcmp (type, "union")) {
		base_type = get_union_type (anal, sname);
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

static void save_struct(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name
		&& type->kind == R_ANAL_BASE_TYPE_KIND_STRUCT);
	char *kind = "struct";
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
	char *sname = r_str_sanitize_sdb_key (type->name);
	// name=struct
	sdb_set (anal->sdb_types, sname, kind, 0);

	RStrBuf *arglist = r_strbuf_new ("");

	int i = 0;
	RAnalStructMember *member;
	R_VEC_FOREACH (&type->struct_data.members, member) {
		// struct.name.param=type,offset,argsize
		char *member_sname = r_str_sanitize_sdb_key (member->name);
		r_strf_var (k, KSZ, "%s.%s.%s", kind, sname, member_sname);
		r_strf_var (v, KSZ, "%s,%u,0", member->type, (unsigned int)member->offset);
		sdb_set (anal->sdb_types, k, v, 0);
		free (member_sname);

		r_strbuf_appendf (arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// struct.name=param1,param2,paramN
	char *key = r_str_newf ("%s.%s", kind, sname);
	if (sdb_exists (anal->sdb_types, key)) {
		R_LOG_DEBUG ("Ignoring overwrite of type '%s' in sdb_types", key);
		r_strbuf_free (arglist);
	} else {
		sdb_set_owned (anal->sdb_types, key, r_strbuf_drain (arglist), 0);
	}

	free (key);
	free (sname);
}

static void save_union(const RAnal *anal, const RAnalBaseType *type) {
	r_strf_buffer (KSZ);
	R_RETURN_IF_FAIL (anal && type && type->name);
	R_RETURN_IF_FAIL (type->kind == R_ANAL_BASE_TYPE_KIND_UNION);
	const char *kind = "union";
	/*
	C:
	union name {type param1; type param2; type paramN;};
	Sdb:
	name=union
	union.name=param1,param2,paramN
	union.name.param1=type,0,0
	union.name.param2=type,0,0
	union.name.paramN=type,0,0
	*/
	RStrBuf *arglist = r_strbuf_new ("");
	char *sname = r_str_sanitize_sdb_key (type->name);
	// name=union
	sdb_set (anal->sdb_types, sname, kind, 0);

	int i = 0;
	RAnalUnionMember *member;
	R_VEC_FOREACH (&type->union_data.members, member) {
		// union.name.arg1=type,offset,argsize
		char *member_sname = r_str_sanitize_sdb_key (member->name);
		r_strf_var (k, KSZ, "%s.%s.%s", kind, sname, member_sname);
		r_strf_var (v, KSZ, "%s,%u,%d", member->type, (unsigned int)member->offset, 0);
		sdb_set (anal->sdb_types, k, v, 0);
		free (member_sname);
		r_strbuf_appendf (arglist, "%s%s", (i++ == 0) ? "" : ",", member->name);
	}
	// union.name=arg1,arg2,argN
	sdb_set_owned (anal->sdb_types, r_strf ("%s.%s", kind, sname), r_strbuf_drain (arglist), 0);
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
		r_strf_var (param_key, KSZ, "enum.%s.%s", sname, case_sname);
		r_strf_var (param_val, KSZ, "0x%" PFMT32x, cas->val);
		r_strf_var (param_key2, KSZ, "enum.%s.0x%" PFMT32x, sname, cas->val);
		sdb_set (anal->sdb_types, param_key, param_val, 0);
		sdb_set (anal->sdb_types, param_key2, case_sname, 0);
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
	sdb_set (anal->sdb_types, r_strf ("type.%s", sname), type->type, 0);
	free (sname);
}

static void save_typedef(const RAnal *anal, const RAnalBaseType *type) {
	r_strf_buffer (KSZ);
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
	sdb_set (anal->sdb_types, r_strf ("typedef.%s", sname), type->type, 0);
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
		RVecAnalStructMember_fini (&type->struct_data.members);
		break;
	case R_ANAL_BASE_TYPE_KIND_UNION:
		RVecAnalUnionMember_fini (&type->union_data.members);
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
			RVecAnalStructMember_init (&type->struct_data.members);
			break;
		case R_ANAL_BASE_TYPE_KIND_ENUM:
			RVecAnalEnumCase_init (&type->enum_data.cases);
			break;
		case R_ANAL_BASE_TYPE_KIND_UNION:
			RVecAnalUnionMember_init (&type->union_data.members);
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
		save_struct (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		save_enum (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_UNION:
		save_union (anal, type);
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
