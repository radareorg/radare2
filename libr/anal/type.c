/* radare - LGPL - Copyright 2019 - pancake, oddcoder, Anton Kochkov */

#include <r_anal.h>
#include <string.h>
#include "sdb/sdb.h"

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

/*!
 * \brief Save the size of the given datatype in sdb
 * \param sdb_types pointer to the sdb for types
 * \param name the datatype whose size if to be stored
 */
static void save_type_size(Sdb *sdb_types, char *name) {
	const char *type = NULL;
	r_return_if_fail (sdb_types && name);
	if (!sdb_exists (sdb_types, name) || !(type = sdb_const_get (sdb_types, name, 0))) {
		return;
	}
	char *type_name_size = r_str_newf ("%s.%s.%s", type, name, "!size");
	r_return_if_fail (type_name_size);
	int size = r_type_get_bitsize (sdb_types, name);
	sdb_set (sdb_types, type_name_size, sdb_fmt ("%d", size), 0);
	free (type_name_size);
}

/*!
 * \brief Save the sizes of the datatypes which have been parsed
 * \param core pointer to radare2 core
 * \param parsed the parsed c string in sdb format
 */
static void __save_parsed_type_size(RAnal *anal, const char *parsed) {
	r_return_if_fail (anal && parsed);
	char *str = strdup (parsed);
	if (str) {
		char *ptr = NULL;
		int offset = 0;
		while ((ptr = strstr (str + offset, "=struct\n")) ||
			(ptr = strstr (str + offset, "=union\n"))) {
			*ptr = 0;
			if (str + offset == ptr) {
				break;
			}
			char *name = ptr - 1;
			while (name > str && *name != '\n') {
				name--;
			}
			if (*name == '\n') {
				name++;
			}
			save_type_size (anal->sdb_types, name);
			*ptr = '=';
			offset = ptr + 1 - str;
		}
		free (str);
	}
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
	__save_parsed_type_size (anal, parsed);
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

static void enum_type_fini(void *e, void *user) {
	(void)user;
	RAnalEnumCase *cas = e;
	free ((char *)cas->name);
}

static void struct_type_fini(void *e, void *user) {
	(void)user;
	RAnalStructMember *member = e;
	free ((char *)member->name);
	free ((char *)member->type);
}

static void union_type_fini(void *e, void *user) {
	(void)user;
	RAnalUnionMember *member = e;
	free ((char *)member->name);
	free ((char *)member->type);
}

static RAnalBaseType *get_enum_type(RAnal *anal, const char *sname) {
	r_return_val_if_fail (anal && sname, NULL);

	RAnalBaseType *base_type = R_NEW0 (RAnalBaseType);
	if (!base_type) {
		return NULL;
	}
	base_type->kind = R_ANAL_BASE_TYPE_KIND_ENUM;

	RAnalBaseTypeEnum base_enum;

	char *members = get_type_data (anal->sdb_types, "enum", sname);
	if (!members) {
		goto error;
	}

	RVector cases;
	r_vector_init (&cases, sizeof (RAnalEnumCase), enum_type_fini, NULL);

	if (!r_vector_reserve (&cases, (size_t)sdb_alen (members))) {
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

		void *element = r_vector_push (&cases, &cas); // returns null if  no space available
		if (!element) {
			goto error;
		}

		sdb_aforeach_next (cur);
	}
	free (members);
	base_enum.cases = cases;
	base_type->enum_data = base_enum;

	return base_type;

error:
	free (base_type);
	free (members);
	r_vector_fini (&cases);
	return NULL;
}

static RAnalBaseType *get_struct_type(RAnal *anal, const char *sname) {
	r_return_val_if_fail (anal && sname, NULL);

	RAnalBaseType *base_type = R_NEW0 (RAnalBaseType);
	if (!base_type) {
		return NULL;
	}
	base_type->kind = R_ANAL_BASE_TYPE_KIND_STRUCT;

	RAnalBaseTypeStruct base_struct;

	char *sdb_members = get_type_data (anal->sdb_types, "struct", sname);
	if (!sdb_members) {
		goto error;
	}

	RVector members;
	r_vector_init (&members, sizeof (RAnalStructMember), struct_type_fini, NULL);

	if (!r_vector_reserve (&members, (size_t)sdb_alen (sdb_members))) {
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

		void *element = r_vector_push (&members, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

		sdb_aforeach_next (cur);
	}
	free (sdb_members);
	base_struct.members = members;
	base_type->struct_data = base_struct;

	return base_type;

error:
	free (base_type);
	free (sdb_members);
	r_vector_fini (&members);
	return NULL;
}

static RAnalBaseType *get_union_type(RAnal *anal, const char *sname) {
	r_return_val_if_fail (anal && sname, NULL);

	RAnalBaseType *base_type = R_NEW0 (RAnalBaseType);
	if (!base_type) {
		return NULL;
	}
	base_type->kind = R_ANAL_BASE_TYPE_KIND_UNION;

	RAnalBaseTypeUnion base_union;

	char *sdb_members = get_type_data (anal->sdb_types, "union", sname);
	if (!sdb_members) {
		goto error;
	}

	RVector members;
	r_vector_init (&members, sizeof (RAnalUnionMember), union_type_fini, NULL);

	if (!r_vector_reserve (&members, (size_t)sdb_alen (sdb_members))) {
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

		void *element = r_vector_push (&members, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

		sdb_aforeach_next (cur);
	}
	free (sdb_members);
	base_union.members = members;
	base_type->union_data = base_union;

	return base_type;

error:
	free (base_type);
	free (sdb_members);
	r_vector_fini (&members);
	return NULL;
}

// returns NULL if name is not found or any failure happened
R_API RAnalBaseType *r_anal_get_base_type(RAnal *anal, const char *name) {
	r_return_val_if_fail (anal && name, NULL);

	char *sname = r_str_sanitize_sdb_key (name);
	const char *type = sdb_const_get (anal->sdb_types, sname, NULL);

	// Right now just types: struct, enum, union are supported
	if (!type || !(strcmp (type, "enum") || strcmp (type, "struct") || strcmp (type, "union"))) {
		free (sname);
		return NULL;
	}
	// Taking advantage that all 3 types start with distinct letter
	// because the strcmp condition guarantees that only those will get to this flow
	RAnalBaseType *base_type = NULL;

	switch (type[0]) {
	case 's': // struct
		base_type = get_struct_type (anal, sname);
		break;
	case 'e': // enum
		base_type = get_enum_type (anal, sname);
		break;
	case 'u': // union
		base_type = get_union_type (anal, sname);
		break;
	}

	free (sname);
	return base_type;
}
