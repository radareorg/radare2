/* radare - LGPL - Copyright 2010-2014 - nibble, pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

// This file contains the reversed api for querying xrefs.c which
// is implemented on top of sdb. Anyway, the sdbization is not
// complete because there's still r_anal_ref_new() which doesnt
// serializes with sdb_native

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
	r_anal_xrefs_set (anal, type, at, addr);
	return R_TRUE;
}

R_API int r_anal_ref_del(RAnal *anal, ut64 at, ut64 addr) {
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_NULL, at, addr);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_CODE, at, addr);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_CALL, at, addr);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_DATA, at, addr);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_STRING, at, addr);
	return R_TRUE;
}

R_API RList *r_anal_xref_get(RAnal *anal, ut64 addr) {
	return r_anal_xrefs_get (anal, addr);
}
