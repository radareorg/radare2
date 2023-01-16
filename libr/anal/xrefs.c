/* radare - LGPL - Copyright 2009-2022 - pancake, nibble, defragger, ret2libc */

#include <r_anal.h>
#include <r_cons.h>

static RAnalRef *r_anal_ref_new(ut64 addr, ut64 at, ut64 type) {
	RAnalRef *ref = R_NEW (RAnalRef);
	if (ref) {
		ref->addr = addr;
		ref->at = at;
		ref->type = (type == UT64_MAX)? R_ANAL_REF_TYPE_CODE: type;
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

// XXX THIS IS HEAVY IN MEMORY USAGE
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
R_API bool r_anal_xrefs_set(RAnal *anal, ut64 from, ut64 to, const RAnalRefType _type) {
	RAnalRefType type = _type;
	r_return_val_if_fail (anal, false);
	if (from == to) {
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
	if (!R_ANAL_REF_TYPE_PERM (type)) {
		// type |= R_ANAL_REF_TYPE_READ;
		switch (R_ANAL_REF_TYPE_MASK (type)) {
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_CALL:
		case R_ANAL_REF_TYPE_JUMP:
			type |= R_ANAL_REF_TYPE_EXEC;
			break;
		default:
			type |= R_ANAL_REF_TYPE_READ;
			break;
		}
	}
	setxref (anal->dict_xrefs, to, from, type);
	setxref (anal->dict_refs, from, to, type);
	R_DIRTY (anal);
	return true;
}

R_API bool r_anal_xrefs_deln(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type) {
	r_return_val_if_fail (anal, false);
#if 0
	ht_up_delete (anal->dict_refs, from);
	ht_up_delete (anal->dict_xrefs, to);
#else
	HtUP *d = ht_up_find (anal->dict_refs, from, NULL);
	if (d) {
		ht_up_delete (d, to);
	}
	d = ht_up_find (anal->dict_xrefs, to, NULL);
	if (d) {
		ht_up_delete (d, from);
	}
#endif
	R_DIRTY (anal);
	return true;
}

R_API bool r_anal_xref_del(RAnal *anal, ut64 from, ut64 to) {
	r_return_val_if_fail (anal, false);
	bool res = false;
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_NULL);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_CODE);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_CALL);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_DATA);
	res |= r_anal_xrefs_deln (anal, from, to, R_ANAL_REF_TYPE_STRING);
	R_DIRTY (anal);
	return res;
}

R_API bool r_anal_xrefs_from(RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	r_return_val_if_fail (anal && list, false);
	listxrefs (anal->dict_refs, addr, list);
	sortxrefs (list);
	return true;
}

R_API RList *r_anal_xrefs_get(RAnal *anal, ut64 to) {
	r_return_val_if_fail (anal, NULL);
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
	r_return_val_if_fail (anal, NULL);
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
	r_return_val_if_fail (anal, NULL);
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

R_API void r_anal_xrefs_list(RAnal *anal, int rad, const char *arg) {
	r_return_if_fail (anal);
	RListIter *iter;
	RAnalRef *ref;
	PJ *pj = NULL;
	RTable *table = NULL;
	RList *list = r_anal_ref_list_new ();
	listxrefs (anal->dict_refs, UT64_MAX, list);
	sortxrefs (list);
	if (rad == ',') {
		table = r_table_new ("xrefs");
		r_table_set_columnsf (table, "ddssss", "from", "to", "type", "perm", "fromname", "toname");
	}
	if (rad == 'j') {
		pj = anal->coreb.pjWithEncoding (anal->coreb.core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	r_list_foreach (list, iter, ref) {
		int t = R_ANAL_REF_TYPE_MASK (ref->type);
		if (!t) {
			t = ' ';
		}
		switch (rad) {
		case ',':
			{
				char *fromname = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
				char *toname = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
				r_table_add_rowf (table, "ddssss",
						ref->at, ref->addr,
						r_anal_ref_type_tostring (t),
						r_anal_ref_perm_tostring (ref),
						toname, fromname
				);
			}
			break;
		case '*':
			// TODO: export/import the read-write-exec information
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
				anal->cb_printf (" 0x%"PFMT64x" > %4s:%s > 0x%"PFMT64x, ref->at,
					r_anal_ref_type_tostring (t), r_anal_ref_perm_tostring (ref), ref->addr);
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
			anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s:%s\n", ref->at, ref->addr,
				r_anal_ref_type_tostring (t), r_anal_ref_perm_tostring (ref));
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
				pj_ks (pj, "type", r_anal_ref_type_tostring (t));
				pj_ks (pj, "perm", r_anal_ref_perm_tostring (ref));
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
	if (rad == ',') {
		if (R_STR_ISNOTEMPTY (arg)) {
			r_table_query (table, arg);
		}
		char *s = r_table_tofancystring (table);
		r_cons_println (s);
		free (s);
		r_table_free (table);
	} else if (rad == 'j') {
		pj_end (pj);
		anal->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	r_list_free (list);
}

R_API char r_anal_ref_perm_tochar(RAnalRef *ref) {
	if (ref->type & R_ANAL_REF_TYPE_WRITE) {
		return 'w';
	}
	if (ref->type & R_ANAL_REF_TYPE_READ) {
		return 'r';
	}
	if (ref->type & R_ANAL_REF_TYPE_EXEC) {
		return 'x';
	}
	switch (R_ANAL_REF_TYPE_MASK (ref->type)) {
	case R_ANAL_REF_TYPE_CODE:
	case R_ANAL_REF_TYPE_CALL:
	case R_ANAL_REF_TYPE_JUMP:
		return 'x';
	}
	return '-';
}

R_API const char *r_anal_ref_perm_tostring(RAnalRef *ref) {
	int perm = R_ANAL_REF_TYPE_PERM (ref->type);
	if (!perm) {
		switch (R_ANAL_REF_TYPE_MASK (ref->type)) {
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_CALL:
		case R_ANAL_REF_TYPE_JUMP:
			perm = R_ANAL_REF_TYPE_EXEC;
			break;
		}
	}
	return r_str_rwx_i (perm);
}

R_API const char *r_anal_ref_type_tostring(RAnalRefType type) {
	switch (R_ANAL_REF_TYPE_MASK (type)) {
	case ' ':
	case R_ANAL_REF_TYPE_NULL:
		return "NULL";
	case R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_DATA:
		return "ICOD"; // indirect code reference
	case R_ANAL_REF_TYPE_CODE:
		return "CODE";
	case R_ANAL_REF_TYPE_CALL:
		return "CALL";
	case R_ANAL_REF_TYPE_JUMP:
		return "JUMP";
	case R_ANAL_REF_TYPE_DATA:
		return "DATA";
	case R_ANAL_REF_TYPE_STRING:
		return "STRN";
	default:
		return "UNKN";
	}
}

R_API RAnalRefType r_anal_xrefs_type_from_string(const char *s) {
	RAnalRefType rt = R_ANAL_REF_TYPE_NULL;
	if (strchr (s, 'r')) {
		rt |= R_ANAL_REF_TYPE_READ | R_ANAL_REF_TYPE_DATA;
	}
	if (strchr (s, 'w')) {
		rt |= R_ANAL_REF_TYPE_WRITE | R_ANAL_REF_TYPE_DATA;
	}
	if (strchr (s, 'x')) {
		rt |= R_ANAL_REF_TYPE_EXEC;
	}
	if (strchr (s, 'c')) {
		rt |= R_ANAL_REF_TYPE_CODE;
	}
	if (strchr (s, 'C')) {
		rt |= R_ANAL_REF_TYPE_CALL;
	}
	if (strchr (s, 'j')) {
		rt |= R_ANAL_REF_TYPE_JUMP;
	}
	if (strchr (s, 'd')) {
		rt |= R_ANAL_REF_TYPE_DATA;
	}
	if (strchr (s, 's')) {
		rt |= R_ANAL_REF_TYPE_STRING;
	}
	return rt;
}

// TODO: deprecate
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
	r_return_val_if_fail (anal, false);
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
