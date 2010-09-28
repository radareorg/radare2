/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalRef *r_anal_ref_new() {
	RAnalRef *ref = R_NEW (RAnalRef);
	if (ref) {
		ref->addr = -1;
		ref->at = -1;
		ref->type = R_ANAL_REF_TYPE_CODE;
	}
	return ref;
}

R_API RList *r_anal_ref_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_ref_free;
	return list;
}

R_API void r_anal_ref_free(void *ref) {
	free (ref);
}

R_API int r_anal_ref_add(RAnal *anal, ut64 addr, ut64 at, int type) {
	RAnalRef *ref = NULL, *refi;
	RListIter *iter;
	int append = 0;
	r_list_foreach (anal->refs, iter, refi)
		if (at == refi->at) {
			ref = refi;
			break;
		}
	if (ref == NULL) {
		if (!(ref = r_anal_ref_new ()))
			return R_FALSE;
		append = 1;
	}
	ref->addr = addr;
	ref->at = at;
	ref->type = type;
	if (append) r_list_append (anal->refs, ref);
	return R_TRUE;
}

R_API int r_anal_ref_del(RAnal *anal, ut64 at) {
	RAnalRef *refi;
	RListIter *iter;
	if (at == 0) {
		r_list_free (anal->refs);
		if (!(anal->refs = r_anal_ref_list_new ()))
			return R_FALSE;
	} else r_list_foreach (anal->refs, iter, refi)
		if (at == refi->at)
			r_list_unlink (anal->refs, refi);
	return R_TRUE;
}

R_API RList *r_anal_xref_get(RAnal *anal, ut64 addr) {
	RAnalFcn *fcni;
	RAnalRef *refi, *ref;
	RListIter *iter, *iter2;
	RList *ret;

	if (!(ret = r_anal_ref_list_new ()))
		return NULL;
	r_list_foreach (anal->fcns, iter, fcni)
		if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
			r_list_foreach (fcni->xrefs, iter2, refi)
				if (refi->at == addr) {
					if (!(ref = r_anal_ref_new ())) {
						r_list_destroy (ret);
						return NULL;
					}
					ref->addr = refi->addr;
					ref->at = refi->at;
					ref->type= refi->type;
					r_list_append (ret, ref);
				}
	r_list_foreach (anal->refs, iter2, refi)
		if (refi->addr == addr) {
			if (!(ref = r_anal_ref_new ())) {
				r_list_destroy (ret);
				return NULL;
			}
			ref->addr = refi->at;
			ref->at = refi->addr;
			ref->type= refi->type;
			r_list_append (ret, ref);
		}
	return ret;
}
