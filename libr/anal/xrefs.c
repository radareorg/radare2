/* radare - LGPL - Copyright 2009-2018 - pancake, nibble, defragger */

#include <r_anal.h>
#include <r_cons.h>

#if 0
DICT
====

refs
  10 -> 20 C
  16 -> 10 J
  20 -> 10 C

xrefs
  20 -> [ 10 C ]
  10 -> [ 16 J, 20 C ]

10: call 20
16: jmp 10
20: call 10
#endif

struct anal_listxrefs_data {
	RAnalRefCmp cmp;
	RList *ret;
	void *data;
};

static const char *analref_toString(RAnalRefType type) {
	switch (type) {
	case R_ANAL_REF_TYPE_NULL:
		/* do nothing */
		break;
	case R_ANAL_REF_TYPE_CODE:
		return "code jmp";
	case R_ANAL_REF_TYPE_CALL:
		return "code call";
	case R_ANAL_REF_TYPE_DATA:
		return "data mem";
	case R_ANAL_REF_TYPE_STRING:
		return "data string";
	}
	return "unk";
}

static int appendRef(dictkv *kv, RList *list) {
	RAnalRef *ref = r_anal_ref_new ();
	if (ref) {
		ref->at = kv->k;
		ref->addr = kv->v;
		if (strcmp (kv->u, "JMP") == 0) {
			ref->type = R_ANAL_REF_TYPE_CODE;
		} else if (strcmp (kv->u, "CALL") == 0) {
			ref->type = R_ANAL_REF_TYPE_CALL;
		} else if (strcmp (kv->u, "DATA") == 0) {
			ref->type = R_ANAL_REF_TYPE_DATA;
		} else if (strcmp (kv->u, "STRING") == 0) {
			ref->type = R_ANAL_REF_TYPE_STRING;
		} else {
			ref->type = R_ANAL_REF_TYPE_NULL;
		}
		r_list_append (list, ref);
	}
	return 0;
}

static int mylistrefs_cb(dictkv *kv, void *u) {
	dict_foreach (kv->u, (dictkv_cb)appendRef, u);
	return 0;
}

static void listxrefs(dict *m, ut64 addr, RList *list) {
	if (addr == UT64_MAX) {
		dict_foreach (m, mylistrefs_cb, list);
	} else {
		dict *d = dict_getu (m, addr);
		if (!d) {
			return;
		}

		dictkv *kv = dict_getr (d, addr);
		if (kv) {
			appendRef (kv, list);
		}
	}
}

static void setxref(dict *m, ut64 from, ut64 to, int type) {
	dictkv *kv = dict_getr (m, from);
	dict *d = NULL;
	if (kv) {
		d = kv->u;
	} else {
		d = R_NEW0 (dict);
		if (d) {
			dict_init (d, 9, NULL);
			dict_set (m, from, to, d);
		}
	}
	dict_set (d, from, to, (void *)r_anal_xrefs_type_tostring (type));
}

static void delref(dict *m, ut64 from, ut64 to, int type) {
	dict_del (m, from);
#if 0
	dictkv *kv = dict_getr (m, from);
	if (kv) {
		dict *ht = kv->u;
		if (ht) {
			dict_del (ht, to);
		}
	}
#endif
}

R_API int r_anal_xrefs_set (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	if (!anal) {
		return false;
	}
	if (!anal->iob.is_valid_offset (anal->iob.io, from, 0)) {
		return false;
	}
	if (!anal->iob.is_valid_offset (anal->iob.io, to, 0)) {
		return false;
	}
	// unknown refs should not be stored. seems wrong
#if 0
	if (type == R_ANAL_REF_TYPE_NULL) {
		return false;
	}
#endif
	setxref (anal->dict_xrefs, to, from, type);
	setxref (anal->dict_refs, from, to, type);
	anal->ref_cache++;
	return true;
}

R_API int r_anal_xrefs_deln (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	if (!anal) {
		return false;
	}
	delref (anal->dict_refs, from, to, type);
	delref (anal->dict_xrefs, to, from, type);
	anal->ref_cache++;
	return true;
}

R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	listxrefs (anal->dict_refs, addr, list);
	return true;
}

static int anal_listrefs_cb(dictkv *kv, struct anal_listxrefs_data *u) {
	RAnalRef ref = {
		.at = kv->k,
		.addr = kv->v,
		.type = (size_t)kv->u
	};
	if (u->cmp (&ref, u->data)) {
		appendRef (kv, u->ret);
	}
	return 0;
}

static int anal_listxrefs_cb(dictkv *kv, struct anal_listxrefs_data *u) {
	dict_foreach (kv->u, (dictkv_cb)anal_listrefs_cb, u);
	return 0;
}

R_API RList *r_anal_xref_get_cb (RAnal *anal, RAnalRefCmp cmp, void *data) {
	RList *ret = r_list_newf (r_anal_ref_free);
	struct anal_listxrefs_data user_data;

	user_data.cmp = cmp;
	user_data.data = data;
	user_data.ret = ret;
	dict_foreach (anal->dict_xrefs, (dictkv_cb)anal_listxrefs_cb, &user_data);
	return ret;
}

R_API RList *r_anal_ref_get_cb (RAnal *anal, RAnalRefCmp cmp, void *data) {
	RList *ret = r_list_newf (r_anal_ref_free);
	struct anal_listxrefs_data user_data;

	user_data.cmp = cmp;
	user_data.data = data;
	user_data.ret = ret;
	dict_foreach (anal->dict_refs, (dictkv_cb)anal_listxrefs_cb, &user_data);
	return ret;
}

R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 to) {
	RList *list = r_list_newf (r_anal_ref_free);
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_xrefs, to, list);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_refs_get (RAnal *anal, ut64 from) {
	RList *list = r_list_newf (r_anal_ref_free);
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_refs, from, list);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_xrefs_get_from (RAnal *anal, ut64 to) {
	RList *list = r_list_newf (NULL);
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_refs, to, list);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API void r_anal_xrefs_list(RAnal *anal, int rad) {
	bool is_first = true;
	RListIter *iter;
	RAnalRef *ref;
	RList *list = r_list_new();
	listxrefs (anal->dict_xrefs, UT64_MAX, list);
	if (rad == 'j') {
		anal->cb_printf ("{");
	}
	r_list_foreach (list, iter, ref) {
		int t = ref->type ? ref->type: ' ';
		switch (rad) {
		case '*':
			anal->cb_printf ("ax%c 0x%"PFMT64x" 0x%"PFMT64x"\n",
				ref->type, ref->at, ref->addr);
			break;
		case '\0':
			{
				char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
				r_str_replace_char (name, ' ', 0);
				anal->cb_printf ("%40s", name? name: "");
				free (name);
				anal->cb_printf (" 0x%"PFMT64x" -> %9s -> 0x%"PFMT64x, ref->at, analref_toString (t), ref->addr);
				name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
				r_str_replace_char (name, ' ', 0);
				if (name && *name) {
					anal->cb_printf (" %s\n", name);
				} else {
					anal->cb_printf ("\n");
				}
				free (name);
			}
			break;
		case 'q':
			anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s\n", ref->at, ref->addr, analref_toString (t));
			break;
		case 'j':
			{
				if (is_first) {
					is_first = false;
				} else {
					anal->cb_printf (",");
				}
				anal->cb_printf ("\"%"PFMT64d"\":%"PFMT64d, ref->at, ref->addr);
			}
			break;
		default:
			break;
		}
	}
	if (rad == 'j') {
		anal->cb_printf ("}\n");
	}
	r_list_free (list);
}

R_API const char *r_anal_xrefs_type_tostring (char type) {
	switch (type) {
	case R_ANAL_REF_TYPE_CODE:
		return "JMP";
	case R_ANAL_REF_TYPE_CALL:
		return "CALL";
	case R_ANAL_REF_TYPE_DATA:
		return "DATA";
	case R_ANAL_REF_TYPE_STRING:
		return "STRING";
	case R_ANAL_REF_TYPE_NULL:
	default:
		return "UNKNOWN";
	}
}

R_API bool r_anal_xrefs_init(RAnal *anal) {
	//TODO
	return true;
}

R_API bool r_anal_xrefs_save(RAnal *anal, const char *prjDir) {
	//TODO
	return true;
}

R_API int r_anal_xrefs_count(RAnal *anal) {
	//TODO implement this
	return 0;
}
