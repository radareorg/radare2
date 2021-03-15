/* radare - LGPL - Copyright 2009-2019 - pancake, nibble, defragger, ret2libc */

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

// XXX: is it possible to have multiple type for the same (from, to) pair?
//      if it is, things need to be adjusted

static RAnalRef *r_anal_ref_new(ut64 addr, ut64 at, ut64 type) {
	RAnalRef *ref = R_NEW (RAnalRef);
	if (ref) {
		ref->addr = addr;
		ref->at = at;
		ref->type = (type == -1)? R_ANAL_REF_TYPE_CODE: type;
	}
	return ref;
}

static void r_anal_ref_free(void *ref) {
	free (ref);
}

R_API RList *r_anal_ref_list_new(void) {
	return r_list_newf (r_anal_ref_free);
}

static void xrefs_ht_free(HtUPKv *kv) {
	ht_up_free (kv->value);
}

static void xrefs_ref_free(HtUPKv *kv) {
	r_anal_ref_free (kv->value);
}

static bool appendRef(void *u, const ut64 k, const void *v) {
	RList *list = (RList *)u;
	RAnalRef *ref = (RAnalRef *)v;
	RAnalRef *cloned = r_anal_ref_new (ref->addr, ref->at, ref->type);
	if (cloned) {
		r_list_append (list, cloned);
		return true;
	}
	return false;
}

static bool mylistrefs_cb(void *list, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach (ht, appendRef, list);
	return true;
}

static int ref_cmp(const RAnalRef *a, const RAnalRef *b) {
	if (a->at < b->at) {
		return -1;
	}
	if (a->at > b->at) {
		return 1;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	if (a->addr > b->addr) {
		return 1;
	}
	return 0;
}

static void sortxrefs(RList *list) {
	r_list_sort (list, (RListComparator)ref_cmp);
}

static void listxrefs(HtUP *m, ut64 addr, RList *list) {
	if (addr == UT64_MAX) {
		ht_up_foreach (m, mylistrefs_cb, list);
	} else {
		bool found;
		HtUP *d = ht_up_find (m, addr, &found);
		if (!found) {
			return;
		}

		ht_up_foreach (d, appendRef, list);
	}
}

static void setxref(HtUP *m, ut64 from, ut64 to, int type) {
	bool found;
	HtUP *ht = ht_up_find (m, from, &found);
	if (!found) {
		ht = ht_up_new (NULL, xrefs_ref_free, NULL);
		if (!ht) {
			return;
		}
		ht_up_insert (m, from, ht);
	}
	RAnalRef *ref = r_anal_ref_new (to, from, type);
	if (ref) {
		ht_up_update (ht, to, ref);
	}
}

// set a reference from FROM to TO and a cross-reference(xref) from TO to FROM.
R_API int r_anal_xrefs_set(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type) {
	if (!anal || from == to) {
		return false;
	}
	if (anal->iob.is_valid_offset) {
		if (!anal->iob.is_valid_offset (anal->iob.io, from, 0)) {
			return false;
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, to, 0)) {
			return false;
		}
	}
	setxref (anal->dict_xrefs, to, from, type);
	setxref (anal->dict_refs, from, to, type);
	return true;
}

R_API int r_anal_xrefs_deln(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type) {
	if (!anal) {
		return false;
	}
	ht_up_delete (anal->dict_refs, from);
	ht_up_delete (anal->dict_xrefs, to);
	return true;
}

R_API int r_anal_xref_del(RAnal *anal, ut64 from, ut64 to) {
	bool res = false;
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_NULL);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_CODE);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_CALL);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_DATA);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_STRING);
	return res;
}

R_API int r_anal_xrefs_from(RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	listxrefs (anal->dict_refs, addr, list);
	sortxrefs (list);
	return true;
}

R_API RList *r_anal_xrefs_get(RAnal *anal, ut64 to) {
	RList *list = r_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_xrefs, to, list);
	sortxrefs (list);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_refs_get(RAnal *anal, ut64 from) {
	RList *list = r_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_refs, from, list);
	sortxrefs (list);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_xrefs_get_from(RAnal *anal, ut64 to) {
	RList *list = r_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_refs, to, list);
	sortxrefs (list);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API void r_anal_xrefs_list(RAnal *anal, int rad) {
	RListIter *iter;
	RAnalRef *ref;
	PJ *pj = NULL;
	RList *list = r_anal_ref_list_new();
	listxrefs (anal->dict_refs, UT64_MAX, list);
	sortxrefs (list);
	if (rad == 'j') {
		pj = anal->coreb.pjWithEncoding (anal->coreb.core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	r_list_foreach (list, iter, ref) {
		int t = ref->type ? ref->type: ' ';
		switch (rad) {
		case '*':
			anal->cb_printf ("ax%c 0x%"PFMT64x" 0x%"PFMT64x"\n", t, ref->addr, ref->at);
			break;
		case '\0':
			{
				char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
				if (name) {
					r_str_replace_ch (name, ' ', 0, true);
					anal->cb_printf ("%40s", name);
					free (name);
				} else {
					anal->cb_printf ("%40s", "?");
				}
				anal->cb_printf (" 0x%"PFMT64x" -> %9s -> 0x%"PFMT64x, ref->at, r_anal_xrefs_type_tostring (t), ref->addr);
				name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
				if (name) {
					r_str_replace_ch (name, ' ', 0, true);
					anal->cb_printf (" %s\n", name);
					free (name);
				} else {
					anal->cb_printf ("\n");
				}
			}
			break;
		case 'q':
			anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s\n", ref->at, ref->addr, r_anal_xrefs_type_tostring (t));
			break;
		case 'j':
			{
				pj_o (pj);
				char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
				if (name) {
					r_str_replace_ch (name, ' ', 0, true);
					pj_ks (pj, "name", name);
					free (name);
				}
				pj_kn (pj, "from", ref->at);
				pj_ks (pj, "type", r_anal_xrefs_type_tostring (t));
				pj_kn (pj, "addr", ref->addr);
				name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
				if (name) {
					r_str_replace_ch (name, ' ', 0, true);
					pj_ks (pj, "refname", name);
					free (name);
				}
				pj_end (pj);
			}
			break;
		default:
			break;
		}
	}
	if (rad == 'j') {
		pj_end (pj);
		anal->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	r_list_free (list);
}

R_API const char *r_anal_xrefs_type_tostring(RAnalRefType type) {
	switch (type) {
	case R_ANAL_REF_TYPE_CODE:
		return "CODE";
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

R_API RAnalRefType r_anal_xrefs_type(char ch) {
	switch (ch) {
	case R_ANAL_REF_TYPE_CODE:
	case R_ANAL_REF_TYPE_CALL:
	case R_ANAL_REF_TYPE_DATA:
	case R_ANAL_REF_TYPE_STRING:
	case R_ANAL_REF_TYPE_NULL:
		return (RAnalRefType)ch;
	default:
		return R_ANAL_REF_TYPE_NULL;
	}
}

R_API bool r_anal_xrefs_init(RAnal *anal) {
	ht_up_free (anal->dict_refs);
	anal->dict_refs = NULL;
	ht_up_free (anal->dict_xrefs);
	anal->dict_xrefs = NULL;

	HtUP *tmp = ht_up_new (NULL, xrefs_ht_free, NULL);
	if (!tmp) {
		return false;
	}
	anal->dict_refs = tmp;

	tmp = ht_up_new (NULL, xrefs_ht_free, NULL);
	if (!tmp) {
		ht_up_free (anal->dict_refs);
		anal->dict_refs = NULL;
		return false;
	}
	anal->dict_xrefs = tmp;
	return true;
}

static bool count_cb(void *user, const ut64 k, const void *v) {
	(*(ut64 *)user) += ((HtUP *)v)->count;
	return true;
}

R_API ut64 r_anal_xrefs_count(RAnal *anal) {
	ut64 ret = 0;
	ht_up_foreach (anal->dict_xrefs, count_cb, &ret);
	return ret;
}

static RList *fcn_get_refs(RAnalFunction *fcn, HtUP *ht) {
	RListIter *iter;
	RAnalBlock *bb;
	RList *list = r_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		int i;

		for (i = 0; i < bb->ninstr; i++) {
			ut64 at = bb->addr + r_anal_bb_offset_inst (bb, i);
			listxrefs (ht, at, list);
		}
	}
	sortxrefs (list);
	return list;
}

R_API RList *r_anal_function_get_refs(RAnalFunction *fcn) {
	r_return_val_if_fail (fcn, NULL);
	return fcn_get_refs (fcn, fcn->anal->dict_refs);
}

R_API RList *r_anal_function_get_xrefs(RAnalFunction *fcn) {
	r_return_val_if_fail (fcn, NULL);
	return fcn_get_refs (fcn, fcn->anal->dict_xrefs);
}

R_API const char *r_anal_ref_type_tostring(RAnalRefType t) {
	switch (t) {
	case R_ANAL_REF_TYPE_NULL:
		return "null";
	case R_ANAL_REF_TYPE_CODE:
		return "code";
	case R_ANAL_REF_TYPE_CALL:
		return "call";
	case R_ANAL_REF_TYPE_DATA:
		return "data";
	case R_ANAL_REF_TYPE_STRING:
		return "string";
	}
	return "unknown";
}
