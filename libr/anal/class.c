/* radare - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_anal.h>
#include <r_vector.h>
#include "../include/r_anal.h"

R_API RAnalClass *r_anal_class_new(const char *name) {
	RAnalClass *cls = R_NEW (RAnalClass);
	if (!cls) {
		return NULL;
	}
	cls->name = name ? strdup (name) : NULL;
	cls->addr = UT64_MAX;
	cls->vtable_addr = UT64_MAX;
	r_vector_init (&cls->base_classes, sizeof (RAnalBaseClass), NULL, NULL);
	r_pvector_init (&cls->methods, (RPVectorFree)r_anal_method_free);
	return cls;
}

R_API void r_anal_class_free(RAnalClass *cls) {
	if (!cls) {
		return;
	}
	free (cls->name);
	r_vector_clear (&cls->base_classes);
	r_pvector_clear (&cls->methods);
	free (cls);
}

R_API RAnalMethod *r_anal_method_new() {
	RAnalMethod *meth = R_NEW (RAnalMethod);
	if (!meth) {
		return NULL;
	}
	meth->addr = UT64_MAX;
	meth->name = NULL;
	meth->vtable_offset = -1;
	return meth;
}

R_API void r_anal_method_free(RAnalMethod *meth) {
	if (!meth) {
		return;
	}
	free (meth->name);
	free (meth);
}


R_API void r_anal_class_add(RAnal *anal, RAnalClass *cls) {
	if (r_pvector_contains (&anal->classes, cls)) {
		return;
	}
	r_pvector_push (&anal->classes, cls);
}

R_API void r_anal_class_remove(RAnal *anal, RAnalClass *cls) {
	ssize_t index = -1;
	size_t i;
	for (i = 0; i < r_pvector_len (&anal->classes); i++) {
		RAnalClass *c = (RAnalClass *)r_pvector_at (&anal->classes, i);
		if (c == cls) {
			index = i;
		}

		size_t j;
		for (j = 0; j < cls->base_classes.len; j++) {
			RAnalBaseClass *base = (RAnalBaseClass *)r_vector_index_ptr (&cls->base_classes, j);
			/* TODO if (base->cls == cls) {
				r_vector_remove_at (&cls->base_classes, j, NULL);
				j++;
			}*/
		}
	}
	if (index >= 0) {
		RAnalClass *c = (RAnalClass *)r_pvector_remove_at (&anal->classes, (size_t)index);
		r_anal_class_free (c);
	}
}

R_API RAnalClass *r_anal_class_get(RAnal *anal, const char *name) {
	void **it;
	r_pvector_foreach (&anal->classes, it) {
		RAnalClass *cls = (RAnalClass *)*it;
		if (strcmp (cls->name, name) == 0) {
			return cls;
		}
	}
	return NULL;
}

// TODO: do we have something like this already somewhere?
static char *flagname(char *name) {
	if (!name) {
		return NULL;
	}
	char *ret = strdup (name);
	if (!ret) {
		return NULL;
	}
	char *cur = ret;
	while (*cur) {
		char c = *cur;
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_') {
			*cur = '_';
		}
		cur++;
	}
	return ret;
}


R_API RAnalMethod *r_anal_class_get_method(RAnalClass *cls, const char *name) {
	void **it;
	r_pvector_foreach (&cls->methods, it) {
		RAnalMethod *meth = *it;
		if (strcmp (meth->name, name) == 0) {
			return meth;
		}
	}
	return NULL;
}





static char *sanitize_id(const char *id) {
	if (!id || !*id) {
		return NULL;
	}
	size_t len = strlen (id);
	char *ret = malloc (len + 1);
	if (!ret) {
		return NULL;
	}
	char *cur = ret;
	while (len > 0) {
		char c = *id;
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')
			&& c != '_' && c != ':') {
			c = '_';
		}
		*cur = c;
		id++;
		cur++;
		len--;
	}
	*cur = '\0';
	return ret;
}

static const char *key_classes = "classes";

static char *key_class(const char *name) {
	return sdb_fmt ("class.%s", name);
}

static char *key_attr_types(const char *name) {
	return sdb_fmt ("attrtypes.%s", name);
}

static char *key_attr_type_attrs(const char *class_name, const char *attr_type) {
	return sdb_fmt ("attr.%s.%s", class_name, attr_type);
}

static char *key_attr_content(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt ("attr.%s.%s.%s", class_name, attr_type, attr_id);
}

static char *key_attr_content_specific(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt ("attr.%s.%s.%s.specific", class_name, attr_type, attr_id);
}

typedef enum {
	R_ANAL_CLASS_ATTR_TYPE_METHOD,
	R_ANAL_CLASS_ATTR_TYPE_VTABLE,
	R_ANAL_CLASS_ATTR_TYPE_BASE
} RAnalClassAttrType;

static const char *attr_type_id(RAnalClassAttrType attr_type) {
	switch (attr_type) {
		case R_ANAL_CLASS_ATTR_TYPE_METHOD:
			return "method";
		case R_ANAL_CLASS_ATTR_TYPE_VTABLE:
			return "vtable";
		case R_ANAL_CLASS_ATTR_TYPE_BASE:
			return "base";
		default:
			return NULL;
	}
}


R_API void r_anal_class_create(RAnal *anal, const char *name) {
	char *name_sanitized = sanitize_id (name);
	if (!name_sanitized) {
		return;
	}
	sdb_array_add (anal->sdb_classes, key_classes, name_sanitized, 0);
	char *key = key_class (name_sanitized);
	free (name_sanitized);
	if (!sdb_exists (anal->sdb_classes, key)) {
		sdb_set (anal->sdb_classes, key, "c", 0);
	}
}


R_API void r_anal_class_delete(RAnal *anal, const char *name) {
	char *class_name_sanitized = sanitize_id (name);
	if (!class_name_sanitized) {
		return;
	}

	sdb_array_remove (anal->sdb_classes, key_classes, class_name_sanitized, 0);

	char *key = key_attr_types (class_name_sanitized);
	char *attr_type_array = sdb_get (anal->sdb_classes, key, 0);

	if (!attr_type_array) {
		free (class_name_sanitized);
		return;
	}

	sdb_array_remove (anal->sdb_classes, key_classes, class_name_sanitized, 0);

	char *attr_type;
	sdb_aforeach (attr_type, attr_type_array) {
		key = key_attr_type_attrs (class_name_sanitized, attr_type);
		char *attr_id_array = sdb_get (anal->sdb_classes, key, 0);
		sdb_remove (anal->sdb_classes, key, 0);
		if (attr_id_array) {
			char *attr_id;
			sdb_aforeach (attr_id, attr_id_array) {
				key = key_attr_content (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes, key, 0);
				key = key_attr_content_specific (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes, key, 0);
				sdb_aforeach_next (attr_id);
			}
		}
		sdb_aforeach_next (attr_type);
	}
	free (attr_type_array);

	sdb_remove (anal->sdb_classes, key_class (class_name_sanitized), 0);
	sdb_remove (anal->sdb_classes, key_attr_types (class_name_sanitized), 0);

	free (class_name_sanitized);
}


// all ids must be sanitized
static char *r_anal_class_get_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key;
	if (specific) {
		key = key_attr_content_specific (class_name, attr_type_str, attr_id);
	} else {
		key = key_attr_content (class_name, attr_type_str, attr_id);
	}
	char *ret = sdb_get (anal->sdb_classes, key, 0);
	return ret;
}

// ids will be sanitized automatically
static char *r_anal_class_get_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return false;
	}
	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return false;
	}

	char *ret = r_anal_class_get_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, specific);

	free (class_name_sanitized);
	free (attr_id_sanitized);

	return ret;
}

// all ids must be sanitized
static RAnalClassErr r_anal_class_set_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	const char *attr_type_str = attr_type_id (attr_type);

	if (!sdb_exists (anal->sdb_classes, key_class (class_name))) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}

	sdb_array_add (anal->sdb_classes, key_attr_types (class_name), attr_type_str, 0);
	sdb_array_add (anal->sdb_classes, key_attr_type_attrs (class_name, attr_type_str), attr_id, 0);
	sdb_set (anal->sdb_classes, key_attr_content (class_name, attr_type_str, attr_id), content, 0);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

// ids will be sanitized automatically
static RAnalClassErr r_anal_class_set_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_set_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, content);

	free (class_name_sanitized);
	free (attr_id_sanitized);

	return err;
}

static RAnalClassErr r_anal_class_delete_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	const char *attr_type_str = attr_type_id (attr_type);

	char *key = key_attr_content (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes, key, 0);
	key = key_attr_content_specific (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes, key, 0);

	key = key_attr_type_attrs (class_name, attr_type_str);
	sdb_array_remove (anal->sdb_classes, key, attr_id, 0);
	if (!sdb_exists (anal->sdb_classes, key)) {
		sdb_array_remove (anal->sdb_classes, key_attr_types (class_name), attr_type_str, 0);
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_delete_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized);

	free (class_name_sanitized);
	free (attr_id_sanitized);
	return err;
}

static RAnalClassErr r_anal_class_rename_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = key_attr_type_attrs (class_name, attr_type_str);

	if (sdb_array_contains (anal->sdb_classes, key, attr_id_new, 0)) {
		return R_ANAL_CLASS_ERR_CLASH;
	}

	if (!sdb_array_remove (anal->sdb_classes, key, attr_id_old, 0)) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	sdb_array_add (anal->sdb_classes, key, attr_id_new, 0);

	key = key_attr_content (class_name, attr_type_str, attr_id_old);
	char *content = sdb_get (anal->sdb_classes, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes, key, 0);
		key = key_attr_content (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes, key, content, 0);
		free (content);
	}

	key = key_attr_content_specific (class_name, attr_type_str, attr_id_old);
	content = sdb_get (anal->sdb_classes, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes, key, 0);
		key = key_attr_content_specific (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes, key, content, 0);
		free (content);
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_rename_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_old_sanitized = sanitize_id (attr_id_old);
	if (!attr_id_old_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_new_sanitized = sanitize_id (attr_id_new);
	if (!attr_id_new_sanitized) {
		free (class_name_sanitized);
		free (attr_id_old_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr ret = r_anal_class_rename_attr_raw (anal, class_name_sanitized, attr_type, attr_id_old_sanitized, attr_id_new_sanitized);
	free (class_name_sanitized);
	free (attr_id_old_sanitized);
	free (attr_id_new_sanitized);
	return ret;
}

static void r_anal_class_unique_attr_id_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, char *out, size_t out_size) {
	ut64 id = 0;
	char *key = key_attr_type_attrs (class_name, attr_type_id (attr_type));
	do {
		snprintf (out, out_size, "%"PFMT64u, id);
		id++;
	} while (sdb_array_contains (anal->sdb_classes, key, out, 0));
}

#if 0
static RAnalClassErr r_anal_class_unique_attr_id(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, char *out, size_t out_size) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	r_anal_class_unique_attr_id_raw (anal, class_name_sanitized, attr_type, out, out_size);
	free (class_name_sanitized);
	return R_ANAL_CLASS_ERR_SUCCESS;
}
#endif

static RAnalClassErr r_anal_class_add_attr_unique_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char attr_id[16];
	r_anal_class_unique_attr_id_raw (anal, class_name, attr_type, attr_id, sizeof(attr_id));

	RAnalClassErr err = r_anal_class_set_attr (anal, class_name, attr_type, attr_id, content);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	if (attr_id_out) {
		r_str_ncpy (attr_id_out, attr_id, attr_id_out_size);
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_add_attr_unique(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_add_attr_unique_raw (anal, class_name_sanitized, attr_type, content, attr_id_out, attr_id_out_size);

	free (class_name_sanitized);
	return err;
}


// ---- METHODS ----
// Format: addr,vtable_offset

R_API void r_anal_class_method_fini(RAnalMethod *meth) {
	free (meth->name);
}

// if the method exists: store it in *meth and return R_ANAL_CLASS_ERR_SUCCESS
// else return the error, contents of *meth are undefined
R_API RAnalClassErr r_anal_class_method_get(RAnal *anal, const char *class_name, const char *meth_name, RAnalMethod *meth) {
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name, false);
	if (!content) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	meth->addr = r_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	meth->vtable_offset = atoi (cur);

	free (content);

	meth->name = sanitize_id (meth_name);
	if (!meth->name) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_method_fini_proxy(void *e, void *user) {
	(void)user;
	RAnalMethod *meth = e;
	r_anal_class_method_fini (meth);
}

R_API RVector/*<RAnalMethod>*/ *r_anal_class_method_get_all(RAnal *anal, const char *class_name) {
	RVector *vec = r_vector_new (sizeof(RAnalMethod), r_anal_class_method_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		r_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name_sanitized, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	free (class_name_sanitized);

	r_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalMethod meth;
		if (r_anal_class_method_get (anal, class_name, cur, &meth) == R_ANAL_CLASS_ERR_SUCCESS) {
			r_vector_push (vec, &meth);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

R_API RAnalClassErr r_anal_class_method_set(RAnal *anal, const char *class_name, RAnalMethod *meth) {
	char *content = sdb_fmt ("%"PFMT64u"%c%d", meth->addr, SDB_RS, meth->vtable_offset);
	return r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth->name, content);
}

R_API RAnalClassErr r_anal_class_method_rename(RAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	return r_anal_class_rename_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, old_meth_name, new_meth_name);
}

R_API RAnalClassErr r_anal_class_method_delete(RAnal *anal, const char *class_name, const char *meth_name) {
	return r_anal_class_delete_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name);
}


// ---- BASE ----

R_API void r_anal_class_base_fini(RAnalBaseClass *base) {
	free (base->id);
	free (base->class_name);
}

R_API RAnalClassErr r_anal_class_base_get(RAnal *anal, const char *class_name, const char *base_id, RAnalBaseClass *base) {
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base_id, false);
	if (!content) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	base->class_name = strdup (cur);
	if (!base->class_name) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	cur = next;
	if (!cur) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	base->offset = r_num_math (NULL, cur);

	free (content);

	base->id = sanitize_id (base_id);
	if (!base->id) {
		free (base->class_name);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_base_fini_proxy(void *e, void *user) {
	(void)user;
	RAnalBaseClass *base = e;
	r_anal_class_base_fini (base);
}

R_API RVector/*<RAnalBaseClass>*/ *r_anal_class_base_get_all(RAnal *anal, const char *class_name) {
	RVector *vec = r_vector_new (sizeof(RAnalBaseClass), r_anal_class_base_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		r_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name_sanitized, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_BASE)), 0);
	free (class_name_sanitized);

	r_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalBaseClass base;
		if (r_anal_class_base_get (anal, class_name, cur, &base) == R_ANAL_CLASS_ERR_SUCCESS) {
			r_vector_push (vec, &base);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

R_API RAnalClassErr r_anal_class_base_set(RAnal *anal, const char *class_name, RAnalBaseClass *base) {
	char *base_class_name_sanitized = sanitize_id (base->class_name);
	if (!base_class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	if (!sdb_exists (anal->sdb_classes, key_class (base_class_name_sanitized))) {
		free (base_class_name_sanitized);
		return R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}

	char *content = sdb_fmt ("%s" SDB_SS "%"PFMT64u, base_class_name_sanitized, base->offset);
	RAnalClassErr err;
	if (base->id) {
		err = r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base->id, content);
	} else {
		base->id = malloc(16);
		if (base->id) {
			err = r_anal_class_add_attr_unique (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, content, base->id, 16);
		} else {
			err = R_ANAL_CLASS_ERR_OTHER;
		}
	}
	free (base_class_name_sanitized);
	return err;
}

R_API RAnalClassErr r_anal_class_base_delete(RAnal *anal, const char *class_name, const char *base_id) {
	return r_anal_class_delete_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base_id);
}



// ---- PRINT ----


static void r_anal_class_print(RAnal *anal, const char *class_name, int mode) {
	bool lng = mode == 'l';
	bool cmd = mode == '*'; // TODO

	r_cons_print (class_name);

	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		bool first = true;
		r_vector_foreach (bases, base) {
			if (first) {
				r_cons_print (": ");
				first = false;
			} else {
				r_cons_print (", ");
			}
			r_cons_print (base->class_name);
		}
		r_vector_free (bases);
	}

	r_cons_print ("\n");


	if (lng) {
		RVector *methods = r_anal_class_method_get_all (anal, class_name);
		if (methods) {
			RAnalMethod *meth;
			r_vector_foreach (methods, meth) {
				r_cons_printf ("  %s @ 0x%"PFMT64x, meth->name, meth->addr);
				if (meth->vtable_offset >= 0) {
					r_cons_printf (" (vtable + 0x%"PFMT64x")\n", (ut64)meth->vtable_offset);
				} else {
					r_cons_print ("\n");
				}
			}
			r_vector_free (methods);
		}
	}



#if 0
	char *fname = NULL;

	if (json) {
		r_cons_printf ("{\"name\":\"%s\"", cls->name);
		if (cls->addr != UT64_MAX) {
			r_cons_printf (",\"addr\":%lld", cls->addr);
		}
		if (cls->vtable_addr != UT64_MAX) {
			r_cons_printf (",\"vtable_addr\":%lld", cls->vtable_addr);
		}
		if (cls->base_classes.len > 0) {
			r_cons_print (",\"bases\":[");
		}
	} else if (cmd) {
		r_cons_print ("fs classes\n");
		fname = flagname (cls->name);
		if (fname) {
			if (cls->vtable_addr != UT64_MAX) {
				r_cons_printf("f class.vtable.%s @ 0x%"PFMT64x"\n", fname, cls->vtable_addr);
			}
			if (cls->addr != UT64_MAX) {
				r_cons_printf("f class.%s @ 0x%"PFMT64x"\n", fname, cls->addr);
			}
		}
	} else {
		r_cons_print (cls->name);
	}

	if (!cmd) {
		size_t i;
		for (i = 0; i < cls->base_classes.len; i++) {
			RAnalBaseClass *bcls = (RAnalBaseClass *)r_vector_index_ptr (&cls->base_classes, i);
			if (i == 0) {
				if (!json) {
					r_cons_print (": ");
				}
			} else {
				if (json) {
					r_cons_print (",");
				} else {
					r_cons_print (", ");
				}
			}

			if (json) {
				r_cons_printf ("{\"name\":\"%s\",\"offset\":%llu}", bcls->cls->name, bcls->offset);
			} else {
				r_cons_print (bcls->cls->name);
			}
		}
	}

	if (json) {
		if (cls->base_classes.len > 0) {
			r_cons_print ("]");
		}
		if (r_pvector_len (&cls->methods) > 0) {
			r_cons_print (",\"methods\":[");
		}
	} else if (!cmd) {
		r_cons_print ("\n");
	}

	if (json || lng || cmd) {
		size_t i;
		for (i = 0; i < r_pvector_len (&cls->methods); i++) {
			RAnalMethod *meth = (RAnalMethod *)r_pvector_at (&cls->methods, i);
			if (json) {
				if (i > 0) {
					r_cons_print (",");
				}
				r_cons_printf ("{\"name\":\"%s\",\"addr\":%lld,\"vtable_offset\":%d}",
							   meth->name, meth->addr, meth->vtable_offset);
			} else if (cmd) {
				char *mfname = flagname (meth->name);
				if (fname && mfname && meth->addr != UT64_MAX) {
					r_cons_printf ("f method.%s.%s @ 0x%"PFMT64x"\n", fname, mfname, meth->addr);
				}
				if (meth->vtable_offset >= 0 && cls->vtable_addr != UT64_MAX) {
					r_cons_printf ("Cd %d @ 0x%"PFMT64x"\n", anal->bits / 8, cls->vtable_addr + meth->vtable_offset);
				}
				free (mfname);
			} else { // lng
				r_cons_printf ("  %s @ 0x%"PFMT64x, meth->name, meth->addr);
				if (meth->vtable_offset >= 0) {
					r_cons_printf (" (vtable +%d)\n", meth->vtable_offset);
				} else {
					r_cons_print ("\n");
				}
			}
		}
	}

	if (json) {
		if (r_pvector_len (&cls->methods) > 0) {
			r_cons_print ("]");
		}
		r_cons_print ("}");
	}
	free (fname);
#endif
}

static void r_anal_class_json(RAnal *anal, PJ *j, const char *class_name) {
	pj_o (j);
	pj_ks (j, "name", class_name);

	pj_k (j, "methods");
	pj_a (j);
	char *array = sdb_get (anal->sdb_classes,
						   key_attr_type_attrs (class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalMethod meth;
		if (r_anal_class_method_get (anal, class_name, cur, &meth) == R_ANAL_CLASS_ERR_SUCCESS) {
			pj_o (j);
			pj_ks (j, "name", cur);
			pj_kn (j, "addr", meth.addr);
			if (meth.vtable_offset >= 0) {
				pj_kn (j, "vtable_offset", (ut64)meth.vtable_offset);
			}
			pj_end (j);
			r_anal_class_method_fini (&meth);
		}
		sdb_aforeach_next (cur);
	}
	free (array);
	pj_end (j);

	pj_end (j);
}

static void r_anal_class_list_json(RAnal *anal) {
	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	pj_a (j);

	char *classes_array = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_name;
	sdb_aforeach (class_name, classes_array) {
		r_anal_class_json (anal, j, class_name);
		sdb_aforeach_next (class_name);
	}
	free (classes_array);

	pj_end (j);
	pj_drain (j);
}

R_API void r_anal_class_list(RAnal *anal, int mode) {
	if (mode == 'j') {
		r_anal_class_list_json (anal);
		return;
	}

	char *classes_array = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_name;
	sdb_aforeach (class_name, classes_array) {
		r_anal_class_print (anal, class_name, mode);
		sdb_aforeach_next (class_name);
	}
	free (classes_array);
}

R_API void r_anal_class_list_bases(RAnal *anal, const char *class_name) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!sdb_exists (anal->sdb_classes, key_class (class_name_sanitized))) {
		return;
	}
	r_cons_printf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	RAnalBaseClass *base;
	r_vector_foreach (bases, base) {
		r_cons_printf ("  %4s %s @ +0x%"PFMT64x"\n", base->id, base->class_name, base->offset);
	}
	r_vector_free (bases);
}