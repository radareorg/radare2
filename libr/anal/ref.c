/* radare - LGPL - Copyright 2010-2015 - nibble, pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

// This file contains the reversed api for querying xrefs.c which
// is implemented on top of sdb. Anyway, the sdbization is not
// complete because there's still r_anal_ref_new() which doesnt
// serializes with sdb_native

R_API RAnalRef *r_anal_ref_new() {
	RAnalRef *ref = R_NEW0 (RAnalRef);
	if (ref) {
		ref->addr = -1;
		ref->at = -1;
		ref->type = R_ANAL_REF_TYPE_CODE;
	}
	return ref;
}

R_API RList *r_anal_ref_list_new() {
	RList *list = r_list_new ();
	if (!list) return NULL;
	list->free = &r_anal_ref_free;
	return list;
}

R_API void r_anal_ref_free(void *ref) {
	free (ref);
}

R_API int r_anal_ref_add(RAnal *anal, ut64 addr, ut64 at, int type) {
	r_anal_xrefs_set (anal, type, at, addr);
	return true;
}

R_API const char *r_anal_ref_to_string(RAnal *anal, int type) {
	switch (type) {
	case R_ANAL_REF_TYPE_NULL: return "null";
	case R_ANAL_REF_TYPE_CODE: return "code";
	case R_ANAL_REF_TYPE_CALL: return "call";
	case R_ANAL_REF_TYPE_DATA: return "data";
	case R_ANAL_REF_TYPE_STRING: return "strg";
	}
	return "unk";
}

R_API int r_anal_ref_del(RAnal *anal, ut64 from, ut64 to) {
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_NULL, from, to);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_CODE, from, to);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_CALL, from, to);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_DATA, from, to);
	r_anal_xrefs_deln (anal, R_ANAL_REF_TYPE_STRING, from, to);
	return true;
}

R_API RList *r_anal_xref_get(RAnal *anal, ut64 addr) {
	return r_anal_xrefs_get (anal, addr);
}
