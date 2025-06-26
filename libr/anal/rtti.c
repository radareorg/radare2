/* radare - LGPL - Copyright 2009-2025 - pancake, maijin, thestr4ng3r */

#include <r_anal.h>
#include <r_core.h>

R_API char *r_anal_rtti_demangle_class_name(RAnal *anal, const char *name) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		return r_anal_rtti_msvc_demangle_class_name (&context, name);
	}
	return r_anal_rtti_itanium_demangle_class_name (&context, name);
}

R_API void r_anal_rtti_print_at_vtable(RAnal *anal, ut64 addr, int mode) {
	bool use_json = mode == 'j';
	RCore *core = anal->coreb.core;
	RCons *cons = core->cons;
	if (use_json) {
		r_cons_print (cons, "[");
	}

	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		r_anal_rtti_msvc_print_at_vtable (&context, addr, mode, false);
	} else {
		r_anal_rtti_itanium_print_at_vtable (&context, addr, mode);
	}

	if (use_json) {
		r_cons_print (cons, "]\n");
	}
}

R_API void r_anal_rtti_print_all(RAnal *anal, int mode) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	RCore *core = anal->coreb.core;
	RCons *cons = core->cons;

	bool use_json = mode == 'j';
	if (use_json) {
		r_cons_print (cons, "[");
	}

	r_cons_break_push (cons, NULL, NULL);
	RList *vtables = r_anal_vtable_search (&context);
	RListIter *vtableIter;
	RVTableInfo *table;

	if (vtables) {
		bool comma = false;
		bool success = false;
		r_list_foreach (vtables, vtableIter, table) {
			if (r_cons_is_breaked (cons)) {
				break;
			}
			if (use_json && success) {
				r_cons_print (cons, ",");
				comma = true;
			}
			if (context.abi == R_ANAL_CPP_ABI_MSVC) {
				success = r_anal_rtti_msvc_print_at_vtable (&context, table->saddr, mode, true);
			} else {
				success = r_anal_rtti_itanium_print_at_vtable (&context, table->saddr, mode);
			}
			if (success) {
				comma = false;
				if (!use_json) {
					r_cons_print (cons, "\n");
				}
			}
		}
		if (use_json && !success && comma) {
			// drop last comma if necessary
			r_cons_drop (cons, 1);
		}
	}
	r_list_free (vtables);
	if (use_json) {
		r_cons_print (cons, "]\n");
	}
	r_cons_break_pop (cons);
}

R_API void r_anal_rtti_recover_all(RAnal *anal) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);

	RCore *core = anal->coreb.core;
	RCons *cons = core->cons;
	r_cons_break_push (cons, NULL, NULL);
	RList *vtables = r_anal_vtable_search (&context);
	if (vtables) {
		if (context.abi == R_ANAL_CPP_ABI_MSVC) {
			r_anal_rtti_msvc_recover_all (&context, vtables);
		} else {
			r_anal_rtti_itanium_recover_all (&context, vtables);
		}
	}
	r_list_free (vtables);
	r_cons_break_pop (cons);
}
