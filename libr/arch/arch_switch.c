/* radare - LGPL - Copyright 2014-2026 - pancake, dso */

#include <r_arch.h>

static RAnalSwitchOp * R_NONNULL __switch_op_new(void) {
	RAnalSwitchOp *swop = R_NEW0 (RAnalSwitchOp);
	swop->cases = r_list_new ();
	swop->cases->free = (void *)free;
	swop->min_val = swop->def_val = swop->max_val = 0;
	swop->vtbl_addr = UT64_MAX;
	swop->jump_addr = UT64_MAX;
	return swop;
}

R_API RAnalSwitchOp *r_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val) {
	RAnalSwitchOp *swop = __switch_op_new ();
	swop->addr = addr;
	swop->min_val = min_val;
	swop->def_val = def_val;
	swop->max_val = max_val;
	return swop;
}

R_API RAnalCaseOp * R_NONNULL r_anal_case_op_new(ut64 addr, ut64 val, ut64 jump) {
	RAnalCaseOp *c = R_NEW0 (RAnalCaseOp);
	c->addr = addr;
	c->value = val;
	c->jump = jump;
	return c;
}

R_API void r_anal_switch_op_free(RAnalSwitchOp *swop) {
	if (R_LIKELY (swop)) {
		r_list_free (swop->cases);
		free (swop);
	}
}

R_API RAnalCaseOp* r_anal_switch_op_add_case(RAnalSwitchOp *swop, ut64 addr, ut64 value, ut64 jump) {
	R_RETURN_VAL_IF_FAIL (swop && addr != UT64_MAX, NULL);
	RAnalCaseOp *caseop = r_anal_case_op_new (addr, value, jump);
	r_list_append (swop->cases, caseop);
	return caseop;
}

R_API bool r_anal_switch_op_add_dep(RAnalSwitchOp *swop, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (swop && addr != UT64_MAX, false);
	if (r_anal_switch_op_has_dep (swop, addr)) {
		return true;
	}
	if (swop->deps_count >= R_ANAL_SWITCH_OP_DEPS) {
		return false;
	}
	swop->deps[swop->deps_count++] = addr;
	return true;
}

R_API bool r_anal_switch_op_has_dep(const RAnalSwitchOp *swop, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (swop && addr != UT64_MAX, false);
	int i;
	for (i = 0; i < swop->deps_count; i++) {
		if (swop->deps[i] == addr) {
			return true;
		}
	}
	return false;
}

R_API void r_anal_switch_spec_init(RAnalSwitchSpec *spec) {
	R_RETURN_IF_FAIL (spec);
	*spec = (RAnalSwitchSpec){0};
	spec->startea = UT64_MAX;
	spec->jtbl_addr = UT64_MAX;
	spec->vtbl_addr = UT64_MAX;
	spec->defjump = UT64_MAX;
	spec->esize = 4;
}

R_API void r_anal_switch_spec_legacy(RAnalSwitchSpec *spec, ut64 startea,
		ut64 tbladdr, ut64 esize, ut64 ncases, ut64 base) {
	R_RETURN_IF_FAIL (spec);
	r_anal_switch_spec_init (spec);
	spec->startea   = startea;
	spec->jtbl_addr = tbladdr;
	spec->esize     = esize ? (ut8)esize : 4;
	spec->ncases    = ncases > R_ANAL_SWITCH_MAXCASES
		? R_ANAL_SWITCH_MAXCASES
		: (ut32)ncases;
	if (base) {
		spec->base = base;
		spec->flags |= R_ANAL_SWITCH_F_BASE;
	}
}
