/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include "r_anal.h"

R_API void r_anal_rtti_print_at_vtable(RAnal *anal, ut64 addr) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		r_anal_rtti_msvc_print_at_vtable (&context, addr);
	} else {
		eprint ("RTTI not supported yet for Itanium.\n");
	}
}

static void rtti_msvc_print_all(RVTableContext *context) {
	RList *vtables = r_anal_vtable_search (context);
	RListIter *vtableIter;
	RVTableInfo *table;

	if (vtables) {
		r_list_foreach (vtables, vtableIter, table) {
				r_anal_rtti_msvc_print_at_vtable (context, table->saddr);
				r_cons_print ("\n");
			}
	}
	r_list_free (vtables);
}

R_API void r_anal_rtti_print_all(RAnal *anal) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		rtti_msvc_print_all (&context);
	} else {
		eprint ("RTTI not supported yet for Itanium.\n");
	}
}
