/* radare - LGPL - Copyright 2010-2014 - nibble, pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

// XXX this .c wraps a reversed xrefs.c api.. this is dupping code. we must merge apis!
// NOTE: This file uses the xrefs api which is sdb based
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

// TODO: use sdb or hashmap for fucks sake
R_API int r_anal_ref_add(RAnal *anal, ut64 addr, ut64 at, int type) {
	const char *types = type=='c'?"jmp":
		type=='C'?"call": type=='s'?"string": "data";
	r_anal_xrefs_set (anal, types, at, addr);
	return R_TRUE;
}

R_API int r_anal_ref_del(RAnal *anal, ut64 at, ut64 addr) {
	r_anal_xrefs_deln (anal, "code", at, addr);
	r_anal_xrefs_deln (anal, "data", at, addr);
	return R_TRUE;
}

R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 addr);
// XXX: MAJOR SLOWDOWN PLZ FIX
R_API RList *r_anal_xref_get(RAnal *anal, ut64 addr) {
	return r_anal_xrefs_get (anal, addr);
}
