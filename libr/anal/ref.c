/* radare - LGPL - Copyright 2010-2013 - nibble, pancake */

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
	RListIter *iter, *iter_tmp;
	if (at == 0) {
		r_list_free (anal->refs);
		if (!(anal->refs = r_anal_ref_list_new ()))
			return R_FALSE;
	} else {
		r_list_foreach_safe (anal->refs, iter, iter_tmp, refi) {
			if (at == refi->at) {
				r_list_delete (anal->refs, iter);
			}
		}
	}
	return R_TRUE;
}

R_API RList *r_anal_xref_get(RAnal *anal, ut64 addr) {
	RAnalFunction *fcni;
	RAnalRef *refi, *ref, *refr;
	RListIter *iter, *iter2, *iter3;
	RList *ret;

	if (!(ret = r_anal_ref_list_new ()))
		return NULL;
	// XXX: this is just a hack that makes analysis/disasm much slower but
	// work as expected. We need to redesign the whole analysis engine :)
	// - find real reverse xrefs by deep walk
	// - addr = our target destination
	r_list_foreach (anal->fcns, iter, fcni) {
		r_list_foreach (fcni->refs, iter2, refi) {
			if (refi->addr == addr) {
				int gonext = 0;
				r_list_foreach (ret, iter3, refr) {
					if (refr->addr == refi->at) // same sauce, so we can skip
						gonext = 1;
				}
				if (gonext) continue;
				// wtf copying xrefs for new lists .. tahts insanely slow
				if (!(ref = r_anal_ref_new ())) {
					r_list_destroy (ret);
					return NULL;
				}
				// NOTE: swapped hacky valuez
				ref->addr = refi->at;
				ref->at = refi->addr;
				ref->type = refi->type;
				r_list_append (ret, ref);
			}
		}
	}
	if (r_list_length (ret)>0)
		return ret;

	r_list_foreach (anal->fcns, iter, fcni) {
		if (addr >= fcni->addr && addr < fcni->addr+fcni->size) {
			r_list_foreach (fcni->xrefs, iter2, refi) {
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
			}
			break; // may break on corner cases
		}
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
