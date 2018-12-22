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
	meth->vtable_index = -1;
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
			if (base->cls == cls) {
				r_vector_remove_at (&cls->base_classes, j, NULL);
				j++;
			}
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

static char *key_attr_type(const char *class_name, const char *attr_type) {
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
	if (!sdb_exists (anal->sdb, key)) {
		sdb_set (anal->sdb_classes, key, "", 0);
	}
}


R_API void r_anal_class_delete(RAnal *anal, const char *name) {
	char *class_name_sanitized = sanitize_id (name);
	if (!class_name_sanitized) {
		return;
	}

	sdb_array_remove (anal->sdb_classes, key_classes, class_name_sanitized, 0);

	char *key = key_class (class_name_sanitized);
	char *attr_type_array = sdb_get (anal->sdb_classes, key, 0);

	if (!attr_type_array) {
		free (class_name_sanitized);
		return;
	}

	sdb_array_remove (anal->sdb_classes, key_classes, class_name_sanitized, 0);

	char *attr_type;
	sdb_aforeach (attr_type, attr_type_array) {
		key = key_attr_type (class_name_sanitized, attr_type);
		char *attr_id_array = sdb_get (anal->sdb_classes, key, 0);
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
static void r_anal_class_set_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	const char *attr_type_str = attr_type_id (attr_type);

	char *key = key_class (class_name);
	sdb_array_add (anal->sdb_classes, key, attr_type_str, 0);

	key = key_attr_type (class_name, attr_type_str);
	sdb_array_add (anal->sdb_classes, key, attr_id, 0);

	key = key_attr_content (class_name, attr_type_str, attr_id);
	sdb_set (anal->sdb_classes, key, content, 0);
}

// ids will be sanitized automatically
static void r_anal_class_set_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return;
	}

	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return;
	}

	r_anal_class_set_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, content);

	free (class_name_sanitized);
	free (attr_id_sanitized);
}

static void r_anal_class_delete_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	const char *attr_type_str = attr_type_id (attr_type);

	char *key = key_attr_content (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb, key, 0);
	key = key_attr_content_specific (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb, key, 0);

	key = key_attr_type (class_name, attr_type_str);
	sdb_array_remove (anal->sdb_classes, key, attr_id, 0);
	if (sdb_array_length (anal->sdb_classes, key) == 0) {
		sdb_remove (anal->sdb_classes, key, 0);
		char *class_key = key_class (class_name);
		if (class_key) {
			sdb_array_remove (anal->sdb_classes, class_key, attr_type_str, 0);
			free (class_key);
		}
	}
}

static void r_anal_class_delete_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return;
	}

	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return;
	}

	r_anal_class_delete_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized);

	free (class_name_sanitized);
	free (attr_id_sanitized);
}



// ---- METHODS ----
// Format: addr,vtable_index

// if the method exists: store it in *meth and return true
// else return false, contents of *meth are undefined
R_API bool r_anal_class_method_get(RAnal *anal, const char *class_name, const char *meth_name, RAnalMethod *meth) {
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name, false);
	if (!content) {
		return false;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	meth->addr = r_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return false;
	}
	sdb_anext (cur, NULL);

	meth->vtable_index = atoi (cur);

	free (content);

	meth->name = sanitize_id (meth_name);
	if (!meth->name) {
		return false;
	}

	return true;
}

R_API void r_anal_class_method_set(RAnal *anal, const char *class_name, RAnalMethod *meth) {
	char *content = sdb_fmt ("%"PFMT64u"%c%d", meth->addr, SDB_RS, meth->vtable_index);
	if (!content) {
		return;
	}
	r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth->name, content);
	free (content);
}

R_API void r_anal_class_method_rename(RAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	// TODO
}

R_API void r_anal_class_method_delete(RAnal *anal, const char *class_name, const char *meth_name) {
	r_anal_class_delete_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name);
}



// ---- PRINT ----


R_API void r_anal_class_print(RAnal *anal, const char *class_name, int mode) {
	bool json = mode == 'j';
	bool lng = mode == 'l';
	bool cmd = mode == '*';

	if (json) {
		r_cons_printf ("\"%s\"", class_name);
	} else {
		r_cons_printf ("%s\n", class_name);
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
				r_cons_printf ("{\"name\":\"%s\",\"addr\":%lld,\"vtable_index\":%d}",
							   meth->name, meth->addr, meth->vtable_index);
			} else if (cmd) {
				char *mfname = flagname (meth->name);
				if (fname && mfname && meth->addr != UT64_MAX) {
					r_cons_printf ("f method.%s.%s @ 0x%"PFMT64x"\n", fname, mfname, meth->addr);
				}
				if (meth->vtable_index >= 0 && cls->vtable_addr != UT64_MAX) {
					r_cons_printf ("Cd %d @ 0x%"PFMT64x"\n", anal->bits / 8, cls->vtable_addr + meth->vtable_index);
				}
				free (mfname);
			} else { // lng
				r_cons_printf ("  %s @ 0x%"PFMT64x, meth->name, meth->addr);
				if (meth->vtable_index >= 0) {
					r_cons_printf (" (vtable +%d)\n", meth->vtable_index);
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

R_API void r_anal_class_list(RAnal *anal, int mode) {
	bool json = mode == 'j';
	if (json) {
		r_cons_print ("[");
	}
	bool first = true;

	char *classes_array = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_name;
	sdb_aforeach (class_name, classes_array) {
		if (json) {
			if (first) {
				first = false;
			} else {
				r_cons_print (",");
			}
		}
		r_anal_class_print (anal, class_name, mode);
		sdb_aforeach_next (class_name);
	}
	free (classes_array);

	if (json) {
		r_cons_print ("]\n");
	}
}


#if R_ANAL_CLASSES_SDB

// escape src and write into dst
// dst must be at least of size strlen(src) * 2 + 1
static size_t escape_id_sdb_into(char *dst, const char *src) {
	if (!src || !dst) {
		return 0;
	}
	char *p = dst;
	char c;
	for (; c = *src, c; src++) {
		switch(*src) {
			case '\\':
				p[0] = '\\';
				p[1] = '\\';
				p += 2;
			case '.':
				p[0] = '\\';
				p[1] = '.';
				p += 2;
			default:
				*p = c;
				p++;
		}
	}
	*p = '\0';
	return p - dst;
}

static char *escape_id_sdb (const char *src) {
	if (!src) {
		return NULL;
	}
	char *r = malloc (strlen(src) * 2 + 1);
	if (!r) {
		return NULL;
	}
	escape_id_sdb_into (r, src);
	return r;
}

static char *id_key_sdb(const char *pre, const char *id, const char *post) {
	size_t pre_len = pre ? strlen(pre) : 0;
	size_t post_len = post ? strlen(post) : 0;
	size_t id_len = id ? strlen(id) : 0;
	char *r = malloc (pre_len + id_len * 2 + post_len + 1);
	if (!r) {
		return NULL;
	}
	char *p = r;
	if (pre) {
		memcpy (p, pre, pre_len);
		p += pre_len;
	}
	if (id) {
		p += escape_id_sdb_into (p, id);
	}
	if (post) {
		memcpy (p, post, post_len);
		p += post_len;
	}
	*p = '\0';
	return r;
}

static const char *class_key(const char *name) {
	char *id = escape_id_sdb (name);
	if (!id) {
		return NULL;
	}
	const char *r = sdb_fmt ("class.%s", name);
	free (id);
	return r;
}

R_API void r_anal_class_set(RAnal *anal, RAnalClass *class) {
	char *name_escaped = r_str_escape (class->name);
	if (!name_escaped) {
		return;
	}

	r_cons_push ();
	r_cons_printf ("{name:\"%s\"", name_escaped);
	free (name_escaped);

	if (class->addr != UT64_MAX) {
		r_cons_printf (",addr:%llu", class->addr);
	}

	if (class->vtable_addr != UT64_MAX) {
		r_cons_printf (",vtable_addr:%llu", class->addr);
	}

	r_cons_print ("}");

	sdb_set (anal->sdb_classes, class_key (class->name), r_cons_get_buffer (), 0);
	r_cons_pop ();
}

static ut64 json_get_ut64 (const char *json, const char *path, ut64 def) {
	char *v = sdb_json_get_str (json, path); // TODO: v does not have to be strduped
	if (!v) {
		return def;
	}
	ut64 r = sdb_atoi (v);
	free (v);
	return r;
}

R_API RAnalClass *r_anal_class_get(RAnal *anal, const char *name) {
	const char *json = sdb_const_get (anal->sdb_classes, class_key (name), 0);
	if (!json) {
		return NULL;
	}

	RAnalClass *cls = r_anal_class_new (NULL);
	if (!cls) {
		return NULL;
	}

	cls->name = sdb_json_get_str (json, "name");
	cls->addr = json_get_ut64 (json, "addr", UT64_MAX);
	cls->vtable_addr = json_get_ut64 (json, "vtable_addr", UT64_MAX);

	return cls;
}

R_API bool r_anal_class_exists(RAnal *anal, const char *name) {
	return sdb_exists (anal->sdb_classes, class_key (name));
}


R_API bool r_anal_class_rename(RAnal *anal, const char *old, const char *new_name) {
	if (!old || !new_name) {
		return false;
	}

	RAnalClass *cls = r_anal_class_get (anal, old);
	if (!cls) {
		return NULL;
	}

	free (cls->name);
	cls->name = strdup (new_name);
	r_anal_class_set (anal, cls);
	return true;
}

#endif