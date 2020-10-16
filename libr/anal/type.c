/* radare - LGPL - Copyright 2019 - pancake, oddcoder, Anton Kochkov */

#include <r_anal.h>
#include <string.h>
#include <sdb.h>
#include "base_types.h"

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
	r_return_if_fail (anal && name);
	Sdb *TDB = anal->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get (TDB, name, 0);
	if (!type) {
		return;
	}
	int tmp_len = strlen (name) + strlen (type);
	char *tmp = malloc (tmp_len + 1);
	r_type_del (TDB, name);
	if (tmp) {
		snprintf (tmp, tmp_len + 1, "%s.%s.", type, name);
		SdbList *l = sdb_foreach_list (TDB, true);
		ls_foreach (l, iter, kv) {
			if (!strncmp (sdbkv_key (kv), tmp, tmp_len)) {
				r_type_del (TDB, sdbkv_key (kv));
			}
		}
		ls_free (l);
		free (tmp);
	}
}

R_API void r_anal_save_parsed_type(RAnal *anal, const char *parsed) {
	r_return_if_fail (anal && parsed);

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

static int typecmp(const void *a, const void *b) {
	return strcmp (a, b);
}

R_API RList *r_anal_types_from_fcn(RAnal *anal, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalVar *var;
	RList *list = r_anal_var_all_list (anal, fcn);
	RList *type_used = r_list_new ();
	r_list_foreach (list, iter, var) {
		r_list_append (type_used, var->type);
	}
	RList *uniq = r_list_uniq (type_used, typecmp);
	r_list_free (type_used);
	return uniq;
}

R_IPI void enum_type_case_free(void *e, void *user) {
	(void)user;
	RAnalEnumCase *cas = e;
	free ((char *)cas->name);
}

R_IPI void struct_type_member_free(void *e, void *user) {
	(void)user;
	RAnalStructMember *member = e;
	free ((char *)member->name);
	free ((char *)member->type);
}

R_IPI void union_type_member_free(void *e, void *user) {
	(void)user;
	RAnalUnionMember *member = e;
	free ((char *)member->name);
	free ((char *)member->type);
}

static RAnalBaseType *get_enum_type(RAnal *anal, const char *sname) {
	r_return_val_if_fail (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}

	char *members = get_type_data (anal->sdb_types, "enum", sname);
	if (!members) {
		goto error;
	}

	RVector *cases = &base_type->enum_data.cases;
	if (!r_vector_reserve (cases, (size_t)sdb_alen (members))) {
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

		void *element = r_vector_push (cases, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

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
	r_return_val_if_fail (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data (anal->sdb_types, "struct", sname);
	if (!sdb_members) {
		goto error;
	}

	RVector *members = &base_type->struct_data.members;
	if (!r_vector_reserve (members, (size_t)sdb_alen (sdb_members))) {
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

		void *element = r_vector_push (members, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

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
	r_return_val_if_fail (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data (anal->sdb_types, "union", sname);
	if (!sdb_members) {
		goto error;
	}

	RVector *members = &base_type->union_data.members;
	if (!r_vector_reserve (members, (size_t)sdb_alen (sdb_members))) {
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

		void *element = r_vector_push (members, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

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
	r_return_val_if_fail (anal && R_STR_ISNOTEMPTY (sname), NULL);

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
	r_return_val_if_fail (anal && R_STR_ISNOTEMPTY (sname), NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return NULL;
	}

	base_type->type = get_type_data (anal->sdb_types, "type", sname);
	if (!base_type->type) {
		goto error;
	}

	RStrBuf key;
	base_type->size = sdb_num_get (anal->sdb_types, r_strbuf_initf (&key, "type.%s.size", sname), 0);
	r_strbuf_fini (&key);

	return base_type;

error:
	r_anal_base_type_free (base_type);
	return NULL;
}

// returns NULL if name is not found or any failure happened
R_API RAnalBaseType *r_anal_get_base_type(RAnal *anal, const char *name) {
	r_return_val_if_fail (anal && name, NULL);

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
	r_return_if_fail (anal && type && type->name
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

	RStrBuf arglist;
	RStrBuf param_key;
	RStrBuf param_val;
	r_strbuf_init (&arglist);
	r_strbuf_init (&param_key);
	r_strbuf_init (&param_val);

	int i = 0;
	RAnalStructMember *member;
	r_vector_foreach (&type->struct_data.members, member) {
		// struct.name.param=type,offset,argsize
		char *member_sname = r_str_sanitize_sdb_key (member->name);
		sdb_set (anal->sdb_types,
			r_strbuf_setf (&param_key, "%s.%s.%s", kind, sname, member_sname),
			r_strbuf_setf (&param_val, "%s,%zu,%d", member->type, member->offset, 0), 0ULL);
		free (member_sname);

		r_strbuf_appendf (&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// struct.name=param1,param2,paramN
	char *key = r_str_newf ("%s.%s", kind, sname);
	sdb_set (anal->sdb_types, key, r_strbuf_get (&arglist), 0);
	free (key);

	free (sname);

	r_strbuf_fini (&arglist);
	r_strbuf_fini (&param_key);
	r_strbuf_fini (&param_val);
}

static void save_union(const RAnal *anal, const RAnalBaseType *type) {
	r_return_if_fail (anal && type && type->name
		&& type->kind == R_ANAL_BASE_TYPE_KIND_UNION);
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
	char *sname = r_str_sanitize_sdb_key (type->name);
	// name=union
	sdb_set (anal->sdb_types, sname, kind, 0);

	RStrBuf arglist;
	RStrBuf param_key;
	RStrBuf param_val;
	r_strbuf_init (&arglist);
	r_strbuf_init (&param_key);
	r_strbuf_init (&param_val);

	int i = 0;
	RAnalUnionMember *member;
	r_vector_foreach (&type->union_data.members, member) {
		// union.name.arg1=type,offset,argsize
		char *member_sname = r_str_sanitize_sdb_key (member->name);
		sdb_set (anal->sdb_types,
			r_strbuf_setf (&param_key, "%s.%s.%s", kind, sname, member_sname),
			r_strbuf_setf (&param_val, "%s,%zu,%d", member->type, member->offset, 0), 0ULL);
		free (member_sname);

		r_strbuf_appendf (&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// union.name=arg1,arg2,argN
	char *key = r_str_newf ("%s.%s", kind, sname);
	sdb_set (anal->sdb_types, key, r_strbuf_get (&arglist), 0);
	free (key);

	free (sname);

	r_strbuf_fini (&arglist);
	r_strbuf_fini (&param_key);
	r_strbuf_fini (&param_val);
}

static void save_enum(const RAnal *anal, const RAnalBaseType *type) {
	r_return_if_fail (anal && type && type->name
		&& type->kind == R_ANAL_BASE_TYPE_KIND_ENUM);
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

	RStrBuf arglist;
	RStrBuf param_key;
	RStrBuf param_val;
	r_strbuf_init (&arglist);
	r_strbuf_init (&param_key);
	r_strbuf_init (&param_val);

	int i = 0;
	RAnalEnumCase *cas;
	r_vector_foreach (&type->enum_data.cases, cas) {
		// enum.name.arg1=type,offset,???
		char *case_sname = r_str_sanitize_sdb_key (cas->name);
		sdb_set (anal->sdb_types,
				r_strbuf_setf (&param_key, "enum.%s.%s", sname, case_sname),
				r_strbuf_setf (&param_val, "0x%" PFMT32x "", cas->val), 0);

		sdb_set (anal->sdb_types,
				r_strbuf_setf (&param_key, "enum.%s.0x%" PFMT32x "", sname, cas->val),
				case_sname, 0);
		free (case_sname);

		r_strbuf_appendf (&arglist, (i++ == 0) ? "%s" : ",%s", cas->name);
	}
	// enum.name=arg1,arg2,argN
	char *key = r_str_newf ("enum.%s", sname);
	sdb_set (anal->sdb_types, key, r_strbuf_get (&arglist), 0);
	free (key);

	free (sname);

	r_strbuf_fini (&arglist);
	r_strbuf_fini (&param_key);
	r_strbuf_fini (&param_val);
}

static void save_atomic_type(const RAnal *anal, const RAnalBaseType *type) {
	r_return_if_fail (anal && type && type->name
		&& type->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "type", 0);

	RStrBuf key;
	RStrBuf val;
	r_strbuf_init (&key);
	r_strbuf_init (&val);

	sdb_set (anal->sdb_types,
			r_strbuf_setf (&key, "type.%s.size", sname),
			r_strbuf_setf (&val, "%" PFMT64u "", type->size), 0);

	sdb_set (anal->sdb_types,
			r_strbuf_setf (&key, "type.%s", sname),
			type->type, 0);

	free (sname);

	r_strbuf_fini (&key);
	r_strbuf_fini (&val);
}
static void save_typedef(const RAnal *anal, const RAnalBaseType *type) {
	r_return_if_fail (anal && type && type->name && type->kind == R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		byte=typedef
		typedef.byte=char
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "typedef", 0);

	RStrBuf key;
	RStrBuf val;
	r_strbuf_init (&key);
	r_strbuf_init (&val);

	sdb_set (anal->sdb_types,
			r_strbuf_setf (&key, "typedef.%s", sname),
			r_strbuf_setf (&val, "%s", type->type), 0);

	free (sname);

	r_strbuf_fini (&key);
	r_strbuf_fini (&val);
}

R_API void r_anal_base_type_free(RAnalBaseType *type) {
	r_return_if_fail (type);
	R_FREE (type->name);
	R_FREE (type->type);

	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
		r_vector_fini (&type->struct_data.members);
		break;
	case R_ANAL_BASE_TYPE_KIND_UNION:
		r_vector_fini (&type->union_data.members);
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		r_vector_fini (&type->enum_data.cases);
		break;
	case R_ANAL_BASE_TYPE_KIND_TYPEDEF:
	case R_ANAL_BASE_TYPE_KIND_ATOMIC:
		break;
	default:
		break;
	}
	R_FREE (type);
}

R_API RAnalBaseType *r_anal_base_type_new(RAnalBaseTypeKind kind) {
	RAnalBaseType *type = R_NEW0 (RAnalBaseType);
	if (!type) {
		return NULL;
	}
	type->kind = kind;
	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
		r_vector_init (&type->struct_data.members, sizeof (RAnalStructMember), struct_type_member_free, NULL);
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		r_vector_init (&type->enum_data.cases, sizeof (RAnalEnumCase), enum_type_case_free, NULL);
		break;
	case R_ANAL_BASE_TYPE_KIND_UNION:
		r_vector_init (&type->union_data.members, sizeof (RAnalUnionMember), union_type_member_free, NULL);
		break;
	default:
		break;
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
	r_return_if_fail (anal && type && type->name);

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
