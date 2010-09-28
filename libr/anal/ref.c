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
