/* radare - LGPL - Copyright 2019 - pancake, oddcoder, Anton Kochkov */

#include <string.h>
#include <r_anal.h>
#include "sdb/sdb.h"

static char* is_type(char *type) {
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
	char *type1 = (char *) a;
	char *type2 = (char *) b;
	return strcmp (type1, type2);
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

static RAnalBaseType *get_enum_type(RAnal *anal, const char *sanitized_name) {
	r_return_val_if_fail (sanitized_name != NULL, NULL);

	RAnalBaseType *base_type = malloc (sizeof (RAnalBaseType));
	if (!base_type) {
		return NULL;
	}
	base_type->kind = R_ANAL_BASE_TYPE_KIND_ENUM;
	
	RAnalBaseTypeEnum base_enum;
	char *key = r_str_newf ("enum.%s", sanitized_name);
	if (!key) {
		free (base_type);
		return NULL;
	}
	char *members = sdb_const_get (anal->sdb_types, key, NULL);
	free (key);

	RVector cases;
	r_vector_init (&cases, sizeof (RAnalEnumCase), enum_type_fini, NULL);

	if (!r_vector_reserve (&cases, (size_t) sdb_alen (members))) {
		free (base_type);
		r_vector_free (&cases);
		return NULL;
	}

	char *cur;
	sdb_aforeach (cur, members) {
		char *val_key = r_str_newf ("enum.%s.%s", sanitized_name, cur);
		char *value = sdb_const_get (anal->sdb_types, val_key, NULL);
		if (!val_key) {
			free (base_type);
			r_vector_fini (&cases);
			return NULL;
		}
		RAnalEnumCase cas = {.name = strdup (cur), .val = strtol (value, NULL, 16)};

		free (val_key);
		
		void *element = r_vector_push (&cases, &cas); // returns null if no space available
		if (!element) {
			free (base_type);
			r_vector_fini (&cases);
			return NULL;
		}

		sdb_aforeach_next (cur);
	}

	base_enum.cases = cases;
	base_type->enum_data = base_enum;

	return base_type;
}

// returns NULL if name is not found or any failure happened
R_API RAnalBaseType *r_anal_get_base_type(RAnal *anal, const char *name) {
	r_return_val_if_fail (name != NULL, NULL);
	r_return_val_if_fail (anal != NULL, NULL);

	char *name_sanitized = r_str_sanitize_sdb_key (name);

	char *type = sdb_const_get (anal->sdb_types, name_sanitized, NULL);

	// Right now just types: struct, enum, union are supported
	if (!type || !(strcmp (type, "enum") || strcmp (type, "struct") || strcmp (type, "union"))) {
		free(name_sanitized);
		return NULL;
	}
	// Taking advantage that all 3 types start with distinct letter
	// because the strcmp condition guarantees that only those will get to this flow
	RAnalBaseType *base_type;
	
	switch (type[0]) {
	case 's': // struct
		break;
	case 'e': // enum
		base_type = get_enum_type (anal, name_sanitized);
		// DEBUG print, TODO not forget to remove
		r_cons_printf ("BaseType: %d\n", base_type->kind);
		RAnalEnumCase *it;
		r_cons_printf("Cases:\n");
		r_vector_foreach (&base_type->enum_data.cases, it) {
			r_cons_printf ("\tname: %s, value: %d\n", it->name, it->val);
		}
		break;
	case 'u': // union
		break;
	}

	free(name_sanitized);
	return base_type;
}
