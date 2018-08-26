/* radare - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_anal.h>
#include <r_vector.h>

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

R_API void r_anal_class_print(RAnal *anal, RAnalClass *cls, int mode) {
	bool json = mode == 'j';
	bool lng = mode == 'l';

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
	} else {
		r_cons_print (cls->name);
	}

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

	if (json) {
		if (cls->base_classes.len > 0) {
			r_cons_print ("]");
		}
		if (r_pvector_len (&cls->methods) > 0) {
			r_cons_print (",\"methods\":[");
		}
	} else {
		r_cons_print ("\n");
	}

	if (json || lng) {
		for (i = 0; i < r_pvector_len (&cls->methods); i++) {
			RAnalMethod *meth = (RAnalMethod *)r_pvector_at (&cls->methods, i);
			if (json) {
				if (i > 0) {
					r_cons_print (",");
				}
				r_cons_printf ("{\"name\":\"%s\",\"addr\":%lld,\"vtable_index\":%d}",
						meth->name, meth->addr, meth->vtable_index);
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
}

R_API void r_anal_class_list(RAnal *anal, int mode) {
	void **it;
	bool json = mode == 'j';
	if (json) {
		r_cons_print ("[");
	}
	bool first = true;
	r_pvector_foreach (&anal->classes, it) {
		if (json) {
			if (first) {
				first = false;
			} else {
				r_cons_print (",");
			}
		}
		RAnalClass *cls = (RAnalClass *)*it;
		r_anal_class_print (anal, cls, mode);
	}
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