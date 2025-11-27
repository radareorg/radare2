/* radare - LGPL - Copyright 2018-2024 - thestr4ng3r */

#include <r_anal.h>

static void r_anal_class_base_delete_class(RAnal *anal, const char *class_name);
static void r_anal_class_method_delete_class(RAnal *anal, const char *class_name);
static void r_anal_class_vtable_delete_class(RAnal *anal, const char *class_name);
static void r_anal_class_base_rename_class(RAnal *anal, const char *class_name_old, const char *class_name_new);
static void r_anal_class_method_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name);
static void r_anal_class_vtable_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name);

static const char *key_class(const char *name) {
	return name;
}

static char *key_attr_types(const char *name) {
	return r_str_newf ("attrtypes.%s", name);
}

static char *key_attr_type_attrs(const char *class_name, const char *attr_type) {
	return r_str_newf ("attr.%s.%s", class_name, attr_type);
}

static char *key_attr_content(const char *class_name, const char *attr_type, const char *attr_id) {
	return r_str_newf ("attr.%s.%s.%s", class_name, attr_type, attr_id);
}

static char *key_attr_content_specific(const char *class_name, const char *attr_type, const char *attr_id) {
	return r_str_newf ("attr.%s.%s.%s.specific", class_name, attr_type, attr_id);
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
	char *name_sanitized = r_str_sanitize_sdb_key (name);
	if (!name_sanitized) {
		return;
	}
	const char *key = key_class (name_sanitized);
	if (!sdb_exists (anal->sdb_classes, key)) {
		sdb_set (anal->sdb_classes, key, "c", 0);
	}

	REventClass event = { .name = name_sanitized };
	r_event_send (anal->ev, R_EVENT_CLASS_ADDED, &event);

	free (name_sanitized);
}


R_API void r_anal_class_delete(RAnal *anal, const char *name) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (name);
	if (!class_name_sanitized) {
		return;
	}

	r_anal_class_base_delete_class (anal, class_name_sanitized);
	r_anal_class_method_delete_class (anal, class_name_sanitized);
	r_anal_class_vtable_delete_class (anal, class_name_sanitized);

	if (!sdb_remove (anal->sdb_classes, key_class (class_name_sanitized), 0)) {
		free (class_name_sanitized);
		return;
	}

	char *key = key_attr_types (class_name_sanitized);
	char *attr_type_array = sdb_get (anal->sdb_classes_attrs, key, 0);

	char *attr_type;
	sdb_aforeach (attr_type, attr_type_array) {
		key = key_attr_type_attrs (class_name_sanitized, attr_type);
		char *attr_id_array = sdb_get (anal->sdb_classes_attrs, key, 0);
		sdb_remove (anal->sdb_classes_attrs, key, 0);
		if (attr_id_array) {
			char *attr_id;
			sdb_aforeach (attr_id, attr_id_array) {
				key = key_attr_content (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes_attrs, key, 0);
				key = key_attr_content_specific (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes_attrs, key, 0);
				sdb_aforeach_next (attr_id);
			}
			free (attr_id_array);
		}
		sdb_aforeach_next (attr_type);
	}
	free (attr_type_array);

	sdb_remove (anal->sdb_classes_attrs, key_attr_types (class_name_sanitized), 0);

	REventClass event = { .name = class_name_sanitized };
	r_event_send (anal->ev, R_EVENT_CLASS_DELETED, &event);

	free (class_name_sanitized);
}

static bool r_anal_class_exists_raw(RAnal *anal, const char *name) {
	return sdb_exists (anal->sdb_classes, key_class (name));
}

R_API bool r_anal_class_exists(RAnal *anal, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal && name, false);
	char *class_name_sanitized = r_str_sanitize_sdb_key (name);
	if (!class_name_sanitized) {
		return false;
	}
	bool r = r_anal_class_exists_raw (anal, class_name_sanitized);
	free (class_name_sanitized);
	return r;
}

R_API SdbList *r_anal_class_get_all(RAnal *anal, bool sorted) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	return sdb_foreach_list (anal->sdb_classes, sorted);
}

R_API void r_anal_class_foreach(RAnal *anal, SdbForeachCallback cb, void *user) {
	sdb_foreach (anal->sdb_classes, cb, user);
}

static bool rename_key(Sdb *sdb, const char *key_old, const char *key_new) {
	char *content = sdb_get (sdb, key_old, 0);
	if (!content) {
		return false;
	}
	sdb_remove (sdb, key_old, 0);
	sdb_set (sdb, key_new, content, 0);
	free (content);
	return true;
}

R_API RAnalClassErr r_anal_class_rename(RAnal *anal, const char *old_name, const char *new_name) {
	R_RETURN_VAL_IF_FAIL (anal && old_name && new_name, R_ANAL_CLASS_ERR_OTHER);
	if (r_anal_class_exists (anal, new_name)) {
		return R_ANAL_CLASS_ERR_CLASH;
	}

	char *old_name_sanitized = r_str_sanitize_sdb_key (old_name);
	if (!old_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *new_name_sanitized = r_str_sanitize_sdb_key (new_name);
	if (!new_name_sanitized) {
		free (old_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = R_ANAL_CLASS_ERR_SUCCESS;

	r_anal_class_base_rename_class (anal, old_name, new_name);
	r_anal_class_method_rename_class (anal, old_name, new_name);
	r_anal_class_vtable_rename_class (anal, old_name, new_name);

	if (!rename_key (anal->sdb_classes, key_class (old_name_sanitized), key_class (new_name_sanitized))) {
		err = R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
		goto beach;
	}

	char *old_name_key = key_attr_types (old_name_sanitized);
	char *attr_types = sdb_get (anal->sdb_classes_attrs, old_name_key, 0);
	free (old_name_key);

	char *attr_type_cur;
	sdb_aforeach (attr_type_cur, attr_types) {
		char *attr_type_attrs_key = key_attr_type_attrs (old_name, attr_type_cur);
		char *attr_ids = sdb_get (anal->sdb_classes_attrs, attr_type_attrs_key, 0);

		char *attr_id_cur;
		sdb_aforeach (attr_id_cur, attr_ids) {
			rename_key (anal->sdb_classes_attrs,
					key_attr_content (old_name, attr_type_cur, attr_id_cur),
					key_attr_content (new_name, attr_type_cur, attr_id_cur));
			sdb_aforeach_next (attr_id_cur);
		}

		free (attr_type_attrs_key);
		free (attr_ids);
		rename_key (anal->sdb_classes_attrs,
				key_attr_type_attrs (old_name, attr_type_cur),
				key_attr_type_attrs (new_name, attr_type_cur));

		sdb_aforeach_next (attr_type_cur);
	}
	free (attr_types);

	rename_key (anal->sdb_classes_attrs, key_attr_types (old_name_sanitized),
			key_attr_types (new_name_sanitized));

	REventClassRename event = {
		.name_old = old_name_sanitized,
		.name_new = new_name_sanitized
	};
	r_event_send (anal->ev, R_EVENT_CLASS_RENAME, &event);

beach:
	free (old_name_sanitized);
	free (new_name_sanitized);
	return err;
}

// all ids must be sanitized
static char *r_anal_class_get_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = specific
		? key_attr_content_specific (class_name, attr_type_str, attr_id)
		: key_attr_content (class_name, attr_type_str, attr_id);
	char *ret = sdb_get (anal->sdb_classes_attrs, key, 0);
	free (key);
	return ret;
}

// ids will be sanitized automatically
static char *r_anal_class_get_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return false;
	}
	char *attr_id_sanitized = r_str_sanitize_sdb_key (attr_id);
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

	if (!r_anal_class_exists_raw (anal, class_name)) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}

	char *attr_types_key = key_attr_types (class_name);
	char *attr_type_attrs_key = key_attr_type_attrs (class_name, attr_type_str);
	char *content_key = key_attr_content (class_name, attr_type_str, attr_id);

	sdb_array_add (anal->sdb_classes_attrs, attr_types_key, attr_type_str, 0);
	sdb_array_add (anal->sdb_classes_attrs, attr_type_attrs_key, attr_id, 0);
	sdb_set (anal->sdb_classes_attrs, content_key, content, 0);

	free (attr_types_key);
	free (attr_type_attrs_key);
	free (content_key);

	REventClassAttrSet event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id
		},
		.content = content
	};
	r_event_send (anal->ev, R_EVENT_CLASS_ATTR_SET, &event);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

// ids will be sanitized automatically
static RAnalClassErr r_anal_class_set_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = r_str_sanitize_sdb_key (attr_id);
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
	sdb_remove (anal->sdb_classes_attrs, key, 0);
	key = key_attr_content_specific (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes_attrs, key, 0);

	key = key_attr_type_attrs (class_name, attr_type_str);
	sdb_array_remove (anal->sdb_classes_attrs, key, attr_id, 0);
	if (!sdb_exists (anal->sdb_classes_attrs, key)) {
		sdb_array_remove (anal->sdb_classes_attrs, key_attr_types (class_name), attr_type_str, 0);
	}

	REventClassAttr event = {
		.class_name = class_name,
		.attr_type = attr_type,
		.attr_id = attr_id
	};
	r_event_send (anal->ev, R_EVENT_CLASS_ATTR_DEL, &event);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_delete_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = r_str_sanitize_sdb_key (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized, attr_type,
			attr_id_sanitized);

	free (class_name_sanitized);
	free (attr_id_sanitized);
	return err;
}

static RAnalClassErr r_anal_class_rename_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = key_attr_type_attrs (class_name, attr_type_str);

	if (sdb_array_contains (anal->sdb_classes_attrs, key, attr_id_new, 0)) {
		return R_ANAL_CLASS_ERR_CLASH;
	}

	if (!sdb_array_remove (anal->sdb_classes_attrs, key, attr_id_old, 0)) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	sdb_array_add (anal->sdb_classes_attrs, key, attr_id_new, 0);

	key = key_attr_content (class_name, attr_type_str, attr_id_old);
	char *content = sdb_get (anal->sdb_classes_attrs, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes_attrs, key, 0);
		key = key_attr_content (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes_attrs, key, content, 0);
		free (content);
	}

	key = key_attr_content_specific (class_name, attr_type_str, attr_id_old);
	content = sdb_get (anal->sdb_classes_attrs, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes_attrs, key, 0);
		key = key_attr_content_specific (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes_attrs, key, content, 0);
		free (content);
	}

	REventClassAttrRename event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id_old
		},
		.attr_id_new = attr_id_new
	};
	r_event_send (anal->ev, R_EVENT_CLASS_ATTR_RENAME, &event);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_rename_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_old_sanitized = r_str_sanitize_sdb_key (attr_id_old);
	if (!attr_id_old_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_new_sanitized = r_str_sanitize_sdb_key (attr_id_new);
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
	} while (sdb_array_contains (anal->sdb_classes_attrs, key, out, 0));
	free (key);
}

static char *flagname_attr(const char *attr_type, const char *class_name, const char *attr_id) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return NULL;
	}
	char *attr_id_sanitized = r_str_sanitize_sdb_key (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return NULL;
	}
	char *r = r_str_newf ("%s.%s.%s", attr_type, class_name, attr_id);
	free (class_name_sanitized);
	free (attr_id_sanitized);
	return r;
}

static void r_anal_class_set_flag(RAnal *anal, const char *name, ut64 addr, ut32 size) {
	if (!name || !anal->flg_class_set) {
		return;
	}
	anal->flg_class_set (anal->flb.f, name, addr, size);
}

static void r_anal_class_unset_flag(RAnal *anal, const char *name) {
	if (!name || !anal->flb.unset_name || !anal->flg_class_get) {
		return;
	}
	if (anal->flg_class_get (anal->flb.f, name)) {
		anal->flb.unset_name (anal->flb.f, name);
	}
}

static void r_anal_class_rename_flag(RAnal *anal, const char *old_name, const char *new_name) {
	if (!old_name || !new_name || !anal->flb.unset || !anal->flg_class_get || !anal->flg_class_set) {
		return;
	}
	RFlagItem *fi = anal->flg_class_get (anal->flb.f, old_name);
	if (fi) {
		const ut64 addr = fi->addr;
		anal->flb.unset (anal->flb.f, fi);
		anal->flg_class_set (anal->flb.f, new_name, addr, 0);
	}
}

static RAnalClassErr r_anal_class_add_attr_unique_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char attr_id[16];
	r_anal_class_unique_attr_id_raw (anal, class_name, attr_type, attr_id, sizeof (attr_id));

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
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_add_attr_unique_raw (anal, class_name_sanitized, attr_type, content, attr_id_out, attr_id_out_size);

	free (class_name_sanitized);
	return err;
}


// ---- METHODS ----
// Format: addr,vtable_offset

static char *flagname_method(const char *class_name, const char *meth_name) {
	return flagname_attr ("method", class_name, meth_name);
}

R_API void r_anal_class_method_fini(RAnalMethod *meth) {
	free (meth->name);
}

// if the method exists: store it in *meth and return R_ANAL_CLASS_ERR_SUCCESS
// else return the error, contents of *meth are undefined
R_API RAnalClassErr r_anal_class_method_get(RAnal *anal, const char *class_name, const char *meth_name, RAnalMethod *meth) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && meth_name && meth, R_ANAL_CLASS_ERR_OTHER);
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

	meth->vtable_offset = atoll (cur);

	free (content);

	meth->name = r_str_sanitize_sdb_key (meth_name);
	if (!meth->name) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}



R_API RVecAnalMethod *r_anal_class_method_get_all(RAnal *anal, const char *class_name) {
	R_RETURN_VAL_IF_FAIL (anal && class_name, NULL);
	RVecAnalMethod *vec = RVecAnalMethod_new ();
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		RVecAnalMethod_free (vec);
		return NULL;
	}
	char *attr_type_attrs_key = key_attr_type_attrs (class_name_sanitized,
			attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD));
	char *array = sdb_get (anal->sdb_classes_attrs, attr_type_attrs_key, 0);
	free (class_name_sanitized);
	free (attr_type_attrs_key);

	int amount = sdb_alen (array);
	if (!RVecAnalMethod_reserve (vec, (size_t) amount?amount:1)) {
		RVecAnalMethod_free (vec);
		return NULL;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalMethod meth;
		if (r_anal_class_method_get (anal, class_name, cur, &meth) == R_ANAL_CLASS_ERR_SUCCESS) {
			RVecAnalMethod_push_back (vec, &meth);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

R_API RAnalClassErr r_anal_class_method_set(RAnal *anal, const char *class_name, RAnalMethod *meth) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && meth, R_ANAL_CLASS_ERR_OTHER);
	char *content = r_str_newf ("%"PFMT64u"%c%"PFMT64d, meth->addr, SDB_RS, meth->vtable_offset);
	RAnalClassErr err = r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth->name, content);
	free (content);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}
	char *flagname = flagname_method (class_name, meth->name);
	r_anal_class_set_flag (anal, flagname, meth->addr, 0);
	free (flagname);
	return R_ANAL_CLASS_ERR_SUCCESS;
}

R_API RAnalClassErr r_anal_class_method_rename(RAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && old_meth_name && new_meth_name, R_ANAL_CLASS_ERR_OTHER);
	RAnalClassErr err = r_anal_class_rename_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, old_meth_name, new_meth_name);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	char *old = flagname_method (class_name, old_meth_name);
	char *new = flagname_method (class_name, new_meth_name);

	r_anal_class_rename_flag (anal, old, new);

	free (old);
	free (new);
	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_method_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (old_class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}

	char *cur;
	sdb_aforeach (cur, array) {
		char *old = flagname_method (old_class_name, cur);
		char *new = flagname_method (new_class_name, cur);
		r_anal_class_rename_flag (anal, old, new);
		free (old);
		free (new);
		sdb_aforeach_next (cur);
	}
	free (array);
}

static void r_anal_class_method_delete_class(RAnal *anal, const char *class_name) {
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		char *flagname = flagname_method (class_name, cur);
		r_anal_class_unset_flag (anal, flagname);
		free (flagname);
		sdb_aforeach_next (cur);
	}
	free (array);
}

R_API RAnalClassErr r_anal_class_method_delete(RAnal *anal, const char *class_name, const char *meth_name) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && meth_name, R_ANAL_CLASS_ERR_OTHER);
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *meth_name_sanitized = r_str_sanitize_sdb_key (meth_name);
	if (!meth_name_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized,
			R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name_sanitized);
	if (err == R_ANAL_CLASS_ERR_SUCCESS) {
		char *flagname = flagname_method (class_name_sanitized, meth_name_sanitized);
		r_anal_class_unset_flag (anal, flagname);
		free (flagname);
	}
	free (class_name_sanitized);
	free (meth_name_sanitized);
	return err;
}


// ---- BASE ----

R_API void r_anal_class_base_fini(RAnalBaseClass *base) {
	free (base->id);
	free (base->class_name);
}

R_API RAnalClassErr r_anal_class_base_get(RAnal *anal, const char *class_name, const char *base_id, RAnalBaseClass *base) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && base_id && base, R_ANAL_CLASS_ERR_OTHER);
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE,
			base_id, false);
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
		free (base->class_name);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	base->offset = r_num_math (NULL, cur);

	free (content);

	base->id = r_str_sanitize_sdb_key (base_id);
	if (!base->id) {
		free (base->class_name);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}



R_API RVecAnalBaseClass *r_anal_class_base_get_all(RAnal *anal, const char *class_name) {
	R_RETURN_VAL_IF_FAIL (anal && class_name, NULL);
	RVecAnalBaseClass *vec = RVecAnalBaseClass_new ();
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		RVecAnalBaseClass_free (vec);
		return NULL;
	}

	char *attr_type_attrs = key_attr_type_attrs (class_name_sanitized,
			attr_type_id (R_ANAL_CLASS_ATTR_TYPE_BASE));
	char *array = sdb_get (anal->sdb_classes_attrs, attr_type_attrs, 0);
	free (class_name_sanitized);
	free (attr_type_attrs);

	int amount = sdb_alen (array);
	if (!RVecAnalBaseClass_reserve (vec, (size_t)(amount > 0)? amount: 1)) {
		RVecAnalBaseClass_free (vec);
		return NULL;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalBaseClass base;
		if (r_anal_class_base_get (anal, class_name, cur, &base) == R_ANAL_CLASS_ERR_SUCCESS) {
			RVecAnalBaseClass_push_back (vec, &base);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

static RAnalClassErr r_anal_class_base_set_raw(RAnal *anal, const char *class_name, RAnalBaseClass *base, const char *base_class_name_sanitized) {
	char *content = r_str_newf ("%s" SDB_SS "%"PFMT64u, base_class_name_sanitized, base->offset);
	RAnalClassErr err;
	if (base->id) {
		err = r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE,
				base->id, content);
	} else {
		base->id = malloc(16);
		if (base->id) {
			err = r_anal_class_add_attr_unique (anal, class_name,
					R_ANAL_CLASS_ATTR_TYPE_BASE, content, base->id, 16);
		} else {
			err = R_ANAL_CLASS_ERR_OTHER;
		}
	}
	free (content);
	return err;
}

R_API RAnalClassErr r_anal_class_base_set(RAnal *anal, const char *class_name, RAnalBaseClass *base) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && base, R_ANAL_CLASS_ERR_OTHER);
	char *base_class_name_sanitized = r_str_sanitize_sdb_key (base->class_name);
	if (!base_class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	if (!r_anal_class_exists_raw (anal, base_class_name_sanitized)) {
		free (base_class_name_sanitized);
		return R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}
	RVecAnalBaseClass *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *existing_base;
		R_VEC_FOREACH (bases, existing_base) {
			if (!strcmp (existing_base->class_name, base->class_name)) {
				free (base_class_name_sanitized);
				RVecAnalBaseClass_free (bases);
				return R_ANAL_CLASS_ERR_OTHER;
			}
		}
	}
	RAnalClassErr err = r_anal_class_base_set_raw (anal, class_name, base, base_class_name_sanitized);
	free (base_class_name_sanitized);
	RVecAnalBaseClass_free (bases);
	return err;
}

R_API RAnalClassErr r_anal_class_base_delete(RAnal *anal, const char *class_name, const char *base_id) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && base_id, R_ANAL_CLASS_ERR_OTHER);
	return r_anal_class_delete_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base_id);
}

typedef struct {
	RAnal *anal;
	const char *class_name;
} DeleteClassCtx;

static bool r_anal_class_base_delete_class_cb(void *user, const char *k, const char *v) {
	(void)v;
	DeleteClassCtx *ctx = user;
	RVecAnalBaseClass *bases = r_anal_class_base_get_all (ctx->anal, k);
	RAnalBaseClass *base;
	R_VEC_FOREACH (bases, base) {
		if (base->class_name && strcmp (base->class_name, ctx->class_name) == 0) {
			r_anal_class_base_delete (ctx->anal, k, base->id);
		}
	}
	RVecAnalBaseClass_free (bases);
	return true;
}

static void r_anal_class_base_delete_class(RAnal *anal, const char *class_name) {
	DeleteClassCtx ctx = { anal, class_name };
	r_anal_class_foreach (anal, r_anal_class_base_delete_class_cb, &ctx);
}

typedef struct {
	RAnal *anal;
	const char *class_name_old;
	const char *class_name_new;
} RenameClassCtx;

static bool r_anal_class_base_rename_class_cb(void *user, const char *k, const char *v) {
	(void)v;
	RenameClassCtx *ctx = user;
	RVecAnalBaseClass *bases = r_anal_class_base_get_all (ctx->anal, k);
	RAnalBaseClass *base;
	R_VEC_FOREACH (bases, base) {
		if (base->class_name && strcmp (base->class_name, ctx->class_name_old) == 0) {
			r_anal_class_base_set_raw (ctx->anal, k, base, ctx->class_name_new);
		}
	}
	RVecAnalBaseClass_free (bases);
	return 1;
}

static void r_anal_class_base_rename_class(RAnal *anal, const char *class_name_old, const char *class_name_new) {
	RenameClassCtx ctx = { anal, class_name_old, class_name_new };
	r_anal_class_foreach (anal, r_anal_class_base_rename_class_cb, &ctx);
}

// ---- VTABLE ----

static char *flagname_vtable(const char *class_name, const char *vtable_id) {
	return flagname_attr ("vtable", class_name, vtable_id);
}

R_API void r_anal_class_vtable_fini(RAnalVTable *vtable) {
	free (vtable->id);
}

R_API RAnalClassErr r_anal_class_vtable_get(RAnal *anal, const char *class_name, const char *vtable_id, RAnalVTable *vtable) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && vtable_id && vtable, R_ANAL_CLASS_ERR_OTHER);
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable_id, false);
	if (!content) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	vtable->addr = r_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, &next);

	vtable->offset = r_num_math (NULL, cur);

	if (next) {
		cur = next;
		sdb_anext (cur, NULL);
		vtable->size = r_num_get (NULL, cur);
	} else {
		vtable->size = 0;
	}

	free (content);

	vtable->id = r_str_sanitize_sdb_key (vtable_id);
	if (!vtable->id) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}



R_API RVecAnalVTable *r_anal_class_vtable_get_all(RAnal *anal, const char *class_name) {
	R_RETURN_VAL_IF_FAIL (anal && class_name, NULL);
	RVecAnalVTable *vec = RVecAnalVTable_new ();
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		RVecAnalVTable_free (vec);
		return NULL;
	}

	char *attr_type_attrs = key_attr_type_attrs (class_name_sanitized,
			attr_type_id (R_ANAL_CLASS_ATTR_TYPE_VTABLE));
	char *array = sdb_get (anal->sdb_classes_attrs, attr_type_attrs, 0);
	free (class_name_sanitized);
	free (attr_type_attrs);

	if (!RVecAnalVTable_reserve (vec, (size_t) sdb_alen (array))) {
		RVecAnalVTable_free (vec);
		return NULL;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalVTable vtable;
		if (r_anal_class_vtable_get (anal, class_name, cur, &vtable) == R_ANAL_CLASS_ERR_SUCCESS) {
			RVecAnalVTable_push_back (vec, &vtable);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

static bool vtable_exists_at(RAnal *anal, const char *class_name, ut64 addr) {
	RVecAnalVTable *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RAnalVTable *existing_vtable;
		R_VEC_FOREACH (vtables, existing_vtable) {
			if (addr == existing_vtable->addr) {
				RVecAnalVTable_free (vtables);
				return true;
			}
		}
	}
	RVecAnalVTable_free (vtables);
	return false;
}

R_API RAnalClassErr r_anal_class_vtable_set(RAnal *anal, const char *class_name, RAnalVTable *vtable) {
	R_RETURN_VAL_IF_FAIL (anal && class_name && vtable, R_ANAL_CLASS_ERR_OTHER);
	if (vtable_exists_at (anal, class_name, vtable->addr)) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *content = r_str_newf ("0x%"PFMT64x SDB_SS "%"PFMT64u SDB_SS "%"PFMT64u, vtable->addr, vtable->offset, vtable->size);
	if (vtable->id) {
		RAnalClassErr err = r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable->id, content);
		free (content);
		return err;
	}
	vtable->id = malloc (16);
	if (!vtable->id) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr err = r_anal_class_add_attr_unique (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_VTABLE, content, vtable->id, 16);
	free (content);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	char *flagname = flagname_vtable (class_name, vtable->id);
	r_anal_class_set_flag (anal, flagname, vtable->addr, vtable->size);
	free (flagname);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_vtable_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name) {
	char *attr_type_attrs = key_attr_type_attrs (old_class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_VTABLE));
	char *array = sdb_get (anal->sdb_classes_attrs, attr_type_attrs, 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		char *old = flagname_vtable (old_class_name, cur);
		char *new = flagname_vtable (new_class_name, cur);

		r_anal_class_rename_flag (anal, old, new);

		free (old);
		free (new);

		sdb_aforeach_next (cur);
	}
	free (array);
}

static void r_anal_class_vtable_delete_class(RAnal *anal, const char *class_name) {
	R_RETURN_IF_FAIL (anal && class_name);
	char *array_key = key_attr_type_attrs (class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_VTABLE));
	char *array = sdb_get (anal->sdb_classes_attrs, array_key, 0);
	free (array_key);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		char *flagname = flagname_vtable (class_name, cur);
		r_anal_class_unset_flag (anal, flagname);
		free (flagname);
		sdb_aforeach_next (cur);
	}
	free (array);
}

R_API RAnalClassErr r_anal_class_vtable_delete(RAnal *anal, const char *class_name, const char *vtable_id) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *vtable_id_sanitized = r_str_sanitize_sdb_key (vtable_id);
	if (!vtable_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized, R_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable_id_sanitized);
	if (err == R_ANAL_CLASS_ERR_SUCCESS) {
		char *flagname = flagname_vtable (class_name_sanitized, vtable_id_sanitized);
		r_anal_class_unset_flag (anal, flagname);
		free (flagname);
	}
	free (class_name_sanitized);
	free (vtable_id_sanitized);
	return err;
}


// ---- PRINT ----

R_API char *r_anal_class_print(RAnal *anal, const char *class_name, bool detailed) {
	RStrBuf *sb = r_strbuf_new (class_name);
	RVecAnalBaseClass *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		bool first = true;
		R_VEC_FOREACH (bases, base) {
			if (first) {
				r_strbuf_append (sb, ": ");
				first = false;
			} else {
				r_strbuf_append (sb, ", ");
			}
			r_strbuf_append (sb, base->class_name);
		}
		RVecAnalBaseClass_free (bases);
	}

	r_strbuf_append (sb, "\n");


	if (detailed) {
		RVecAnalVTable *vtables = r_anal_class_vtable_get_all (anal, class_name);
		if (vtables) {
			RAnalVTable *vtable;
			R_VEC_FOREACH (vtables, vtable) {
				r_strbuf_appendf (sb, "  (vtable at 0x%"PFMT64x, vtable->addr);
				if (vtable->offset > 0) {
					r_strbuf_appendf (sb, " in class at +0x%"PFMT64x")\n", vtable->offset);
				} else {
					r_strbuf_append (sb, ")\n");
				}
			}
			RVecAnalVTable_free (vtables);
		}

		RVecAnalMethod *methods = r_anal_class_method_get_all (anal, class_name);
		if (methods) {
			RAnalMethod *meth;
			R_VEC_FOREACH (methods, meth) {
				r_strbuf_appendf (sb, "  %s @ 0x%"PFMT64x, meth->name, meth->addr);
				if (meth->vtable_offset >= 0) {
					r_strbuf_appendf (sb, " (vtable + 0x%"PFMT64x")\n", (ut64)meth->vtable_offset);
				} else {
					r_strbuf_append (sb, "\n");
				}
			}
			RVecAnalMethod_free (methods);
		}
	}
	return r_strbuf_drain (sb);
}

static void print_class(RAnal *anal, RStrBuf *sb, const char *class_name) {
	RVecAnalBaseClass *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		R_VEC_FOREACH (bases, base) {
			r_strbuf_appendf (sb, "'acb %s %s %"PFMT64u"\n", class_name, base->class_name, base->offset);
		}
		RVecAnalBaseClass_free (bases);
	}

	RVecAnalVTable *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RAnalVTable *vtable;
		R_VEC_FOREACH (vtables, vtable) {
			r_strbuf_appendf (sb, "'acv %s 0x%"PFMT64x" %"PFMT64u"\n", class_name, vtable->addr, vtable->offset);
		}
		RVecAnalVTable_free (vtables);
	}

	RVecAnalMethod *methods = r_anal_class_method_get_all (anal, class_name);
	if (methods) {
		RAnalMethod *meth;
		R_VEC_FOREACH (methods, meth) {
			r_strbuf_appendf (sb, "'acm %s %s 0x%"PFMT64x" %"PFMT64d"\n", class_name, meth->name, meth->addr, meth->vtable_offset);
		}
		RVecAnalMethod_free (methods);
	}
}

R_API void r_anal_class_json(RAnal *anal, PJ *j, const char *class_name) {
	pj_o (j);
	pj_ks (j, "name", class_name);

	pj_k (j, "bases");
	pj_a (j);
	RVecAnalBaseClass *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		R_VEC_FOREACH (bases, base) {
			pj_o (j);
			pj_ks (j, "id", base->id);
			pj_ks (j, "name", base->class_name);
			pj_kn (j, "offset", base->offset);
			pj_end (j);
		}
		RVecAnalBaseClass_free (bases);
	}
	pj_end (j);

	pj_k (j, "vtables");
	pj_a (j);
	RVecAnalVTable *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RAnalVTable *vtable;
		R_VEC_FOREACH (vtables, vtable) {
			pj_o (j);
			pj_ks (j, "id", vtable->id);
			pj_kn (j, "addr", vtable->addr);
			pj_kn (j, "offset", vtable->offset);
			pj_end (j);
		}
		RVecAnalVTable_free (vtables);
	}
	pj_end (j);

	pj_k (j, "methods");
	pj_a (j);
	RVecAnalMethod *methods = r_anal_class_method_get_all (anal, class_name);
	if (methods) {
		RAnalMethod *meth;
		R_VEC_FOREACH (methods, meth) {
			pj_o (j);
			pj_ks (j, "name", meth->name);
			pj_kn (j, "addr", meth->addr);
			if (meth->vtable_offset >= 0) {
				pj_kn (j, "vtable_offset", (ut64)meth->vtable_offset);
			}
			pj_end (j);
		}
		RVecAnalMethod_free (methods);
	}
	pj_end (j);

	pj_end (j);
}

typedef struct {
	RAnal *anal;
	PJ *j;
} ListJsonCtx;

static bool r_anal_class_list_json_cb(void *user, const char *k, const char *v) {
	ListJsonCtx *ctx = user;
	r_anal_class_json (ctx->anal, ctx->j, k);
	return true;
}

static char *r_anal_class_list_json(RAnal *anal) {
	PJ *j = anal->coreb.pjWithEncoding (anal->coreb.core);
	if (!j) {
		return NULL;
	}
	pj_a (j);

	ListJsonCtx ctx;
	ctx.anal = anal;
	ctx.j = j;
	r_anal_class_foreach (anal, r_anal_class_list_json_cb, &ctx);

	pj_end (j);
	return pj_drain (j);
}

R_API char *r_anal_class_list(RAnal *anal, int mode) {
	if (mode == 'j') {
		return r_anal_class_list_json (anal);
	}

	SdbList *classes = r_anal_class_get_all (anal, mode != '*');
	SdbListIter *iter;
	SdbKv *kv;
	RStrBuf *sb = r_strbuf_new ("");
	if (mode == '*') {
		ls_foreach (classes, iter, kv) {
			// need to create all classes first, so they can be referenced
			r_strbuf_appendf (sb, "'ac %s\n", sdbkv_key (kv));
		}
		ls_foreach (classes, iter, kv) {
			print_class (anal, sb, sdbkv_key (kv));
		}
	} else {
		ls_foreach (classes, iter, kv) {
			char *s = r_anal_class_print (anal, sdbkv_key (kv), mode == 'l');
			r_strbuf_append (sb, s);
			free (s);
		}
	}
	ls_free (classes);
	return r_strbuf_drain (sb);
}

R_API char *r_anal_class_list_bases(RAnal *anal, const char *class_name) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return NULL;
	}
	if (!r_anal_class_exists_raw (anal, class_name_sanitized)) {
		free (class_name_sanitized);
		return NULL;
	}
	RStrBuf *sb = r_strbuf_newf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RVecAnalBaseClass *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		R_VEC_FOREACH (bases, base) {
			r_strbuf_appendf (sb, "  %4s %s @ +0x%"PFMT64x"\n", base->id, base->class_name, base->offset);
		}
		RVecAnalBaseClass_free (bases);
	}
	return r_strbuf_drain (sb);
}

R_API char *r_anal_class_list_vtables(RAnal *anal, const char *class_name) {
	char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return NULL;
	}
	if (!r_anal_class_exists_raw (anal, class_name_sanitized)) {
		free (class_name_sanitized);
		return NULL;
	}
	RStrBuf *sb = r_strbuf_newf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RVecAnalVTable *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RAnalVTable *vtable;
		R_VEC_FOREACH (vtables, vtable) {
			r_strbuf_appendf (sb, "  %4s vtable 0x%"PFMT64x" @ +0x%"PFMT64x" size:+0x%"PFMT64x"\n",
					vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		RVecAnalVTable_free (vtables);
	}
	return r_strbuf_drain (sb);
}

static void list_all_functions_at_vtable_offset(RAnal *anal, const char *class_name, ut64 offset, RStrBuf *sb) {
	RVTableContext vtableContext;
	r_anal_vtable_begin (anal, &vtableContext);
	ut8 function_ptr_size = vtableContext.word_size;
	RVecAnalVTable *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (!vtables) {
		return;
	}

	ut64 func_address;
	RAnalVTable *vtable;
	R_VEC_FOREACH (vtables, vtable) {
		if (vtable->size < offset + function_ptr_size) {
			continue;
		}
		if (vtableContext.read_addr(anal, vtable->addr+offset, &func_address))
			r_strbuf_appendf (sb, "Function address: 0x%08"PFMT64x", in %s vtable %s\n",
					func_address, class_name, vtable->id);
	}
	RVecAnalVTable_free (vtables);
}

R_API char *r_anal_class_list_vtable_offset_functions(RAnal *anal, const char *class_name, ut64 offset) {
	RStrBuf *sb = r_strbuf_new ("");
	if (class_name) {
		char *class_name_sanitized = r_str_sanitize_sdb_key (class_name);
		if (!class_name_sanitized) {
			goto beach;
		}
		if (!r_anal_class_exists_raw (anal, class_name_sanitized)) {
			free (class_name_sanitized);
			goto beach;
		}
		free (class_name_sanitized);

		list_all_functions_at_vtable_offset (anal, class_name, offset, sb);
	} else {
		SdbList *classes = r_anal_class_get_all (anal, true);
		SdbListIter *iter;
		SdbKv *kv;
		ls_foreach (classes, iter, kv) {
			const char *name = sdbkv_key (kv);
			list_all_functions_at_vtable_offset (anal, name, offset, sb);
		}
		ls_free (classes);
	}
beach:
	return r_strbuf_drain (sb);
}

/**
 * @brief Creates RGraph from class inheritance information where
 *        each node has RGraphNodeInfo as generic data
 *
 * @param anal
 * @return RGraph* NULL if failure
 */
R_API RGraph *r_anal_class_get_inheritance_graph(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RGraph *class_graph = r_graph_new ();
	if (!class_graph) {
		return NULL;
	}
	SdbList *classes = r_anal_class_get_all (anal, true);
	if (!classes) {
		r_graph_free (class_graph);
		return NULL;
	}
	HtPP /*<char *name, RGraphNode *node>*/ *hashmap = ht_pp_new0 ();
	if (!hashmap) {
		r_graph_free (class_graph);
		ls_free (classes);
		return NULL;
	}
	SdbListIter *iter;
	SdbKv *kv;
	// Traverse each class and create a node and edges
	ls_foreach (classes, iter, kv) {
		const char *name = sdbkv_key (kv);
		// create nodes
		RGraphNode *curr_node = ht_pp_find (hashmap, name, NULL);
		if (!curr_node) {
			curr_node = r_graph_add_node_info (class_graph, name, NULL, 0);
			if (!curr_node) {
				goto failure;
			}
			ht_pp_insert (hashmap, name, curr_node);
		}
		// create edges between node and it's parents
		RVecAnalBaseClass *bases = r_anal_class_base_get_all (anal, name);
		if (!bases) {
			goto failure;
		}
		RAnalBaseClass *base;
		R_VEC_FOREACH (bases, base) {
			bool base_found = false;
			RGraphNode *base_node = ht_pp_find (hashmap, base->class_name, &base_found);
			// If base isn't processed, do it now
			if (!base_found) {
				base_node = r_graph_add_node_info (class_graph, base->class_name, NULL, 0);
				if (!base_node) {
					goto failure;
				}
				ht_pp_insert (hashmap, base->class_name, base_node);
			}
			r_graph_add_edge (class_graph, base_node, curr_node);
		}
		RVecAnalBaseClass_free (bases);
	}
	ls_free (classes);
	ht_pp_free (hashmap);
	return class_graph;

failure:
	ls_free (classes);
	ht_pp_free (hashmap);
	r_graph_free (class_graph);
	return NULL;
}
