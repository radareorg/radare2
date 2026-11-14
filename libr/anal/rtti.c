/* radare - LGPL - Copyright 2009-2025 - pancake, maijin, thestr4ng3r */

#include <r_anal.h>

R_IPI char *r_anal_rtti_msvc_demangle_class_name(RVTableContext *context, const char *name);
R_IPI char *r_anal_rtti_itanium_demangle_class_name(RVTableContext *context, const char *name);
R_IPI bool r_anal_rtti_msvc_print_at_vtable(RVTableContext *context, ut64 addr, RStrBuf *sb, PJ *pj, bool strict);
R_IPI bool r_anal_rtti_itanium_print_at_vtable(RVTableContext *context, ut64 addr, RStrBuf *sb, PJ *pj);
R_IPI void r_anal_rtti_msvc_recover_all(RVTableContext *context, RList *vtables);
R_IPI void r_anal_rtti_itanium_recover_all(RVTableContext *context, RList *vtables);

R_API char *r_anal_rtti_demangle_class_name(RAnal *anal, const char *name) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		return r_anal_rtti_msvc_demangle_class_name (&context, name);
	}
	return r_anal_rtti_itanium_demangle_class_name (&context, name);
}

static bool rtti_print_at_vtable(RVTableContext *context, ut64 addr, RStrBuf *sb, PJ *pj, bool strict) {
	if (context->abi == R_ANAL_CPP_ABI_MSVC) {
		return r_anal_rtti_msvc_print_at_vtable (context, addr, sb, pj, strict);
	}
	return r_anal_rtti_itanium_print_at_vtable (context, addr, sb, pj);
}

R_API R_OWNED char *r_anal_rtti_print_at_vtable(RAnal *anal, ut64 addr, int mode) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	RStrBuf sb;
	r_strbuf_init (&sb);
	PJ *pj = mode == 'j'? pj_new (): NULL;
	if (pj) {
		pj_a (pj);
	}
	rtti_print_at_vtable (&context, addr, &sb, pj, false);
	if (pj) {
		pj_end (pj);
		pj_raw (pj, "\n");
		return pj_drain (pj);
	}
	return r_strbuf_drain_nofree (&sb);
}

R_API R_OWNED char *r_anal_rtti_print_all(RAnal *anal, int mode) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	RStrBuf sb;
	r_strbuf_init (&sb);
	PJ *pj = mode == 'j'? pj_new (): NULL;
	if (pj) {
		pj_a (pj);
	}

	RList *vtables = r_anal_vtable_search (&context);
	RListIter *vtable_iter;
	RVTableInfo *table;
	r_list_foreach (vtables, vtable_iter, table) {
		if (r_print_is_interrupted (anal->print)) {
			break;
		}
		if (rtti_print_at_vtable (&context, table->saddr, &sb, pj, true) && !pj) {
			r_strbuf_append (&sb, "\n");
		}
	}
	r_list_free (vtables);
	if (pj) {
		pj_end (pj);
		pj_raw (pj, "\n");
		return pj_drain (pj);
	}
	return r_strbuf_drain_nofree (&sb);
}

R_API void r_anal_rtti_recover_all(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);

	RList *vtables = r_anal_vtable_search (&context);
	if (vtables) {
		if (context.abi == R_ANAL_CPP_ABI_MSVC) {
			r_anal_rtti_msvc_recover_all (&context, vtables);
		} else {
			r_anal_rtti_itanium_recover_all (&context, vtables);
		}
	}
	r_list_free (vtables);
}
