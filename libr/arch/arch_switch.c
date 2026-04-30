/* radare - LGPL - Copyright 2014-2025 - pancake, dso */

#include <r_arch.h>

#if 0
static RArchSwitchOp *__switch_op_new(void) {
	RArchSwitchOp * swop = R_NEW0 (RArchSwitchOp);
	if (swop) {
		swop->cases = r_list_new ();
		if (!swop->cases) {
			free (swop);
			return NULL;
		}
		swop->cases->free = (void *)free;
		swop->min_val = swop->def_val = swop->max_val = 0;
	}
	return swop;
}

R_API RArchSwitchOp *r_arch_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val) {
	RArchSwitchOp *swop = __switch_op_new ();
	if (swop) {
		swop->addr = addr;
		swop->min_val = min_val;
		swop->def_val = def_val;
		swop->max_val = max_val;
	}
	return swop;
}

R_API RArchCaseOp *r_arch_case_op_new(ut64 addr, ut64 val, ut64 jump) {
	RArchCaseOp *c = R_NEW0 (RArchCaseOp);
	if (c) {
		c->addr = addr;
		c->value = val;
		c->jump = jump;
	}
	return c;
}

R_API void r_arch_switch_op_free(RArchSwitchOp *swop) {
	if (swop) {
		r_list_free (swop->cases);
		free (swop);
	}
}

R_API RArchCaseOp* r_arch_switch_op_add_case(RArchSwitchOp *swop, ut64 addr, ut64 value, ut64 jump) {
	R_RETURN_VAL_IF_FAIL (swop && addr != UT64_MAX, NULL);
	RArchCaseOp * caseop = r_arch_case_op_new (addr, value, jump);
	if (caseop) {
		r_list_append (swop->cases, caseop);
	}
	return caseop;
}
#endif

static RAnalSwitchOp * R_NONNULL __switch_op_new(void) {
	RAnalSwitchOp *swop = R_NEW0 (RAnalSwitchOp);
	swop->cases = r_list_new ();
	swop->cases->free = (void *)free;
	swop->min_val = swop->def_val = swop->max_val = 0;
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
		free (swop->reg);
		free (swop);
	}
}

R_API RAnalCaseOp* r_anal_switch_op_add_case(RAnalSwitchOp *swop, ut64 addr, ut64 value, ut64 jump) {
	R_RETURN_VAL_IF_FAIL (swop && addr != UT64_MAX, NULL);
	RAnalCaseOp *caseop = r_anal_case_op_new (addr, value, jump);
	r_list_append (swop->cases, caseop);
	return caseop;
}

R_API void r_anal_switch_spec_init(RAnalSwitchSpec *spec) {
	R_RETURN_IF_FAIL (spec);
	memset (spec, 0, sizeof (*spec));
	spec->startea   = UT64_MAX;
	spec->jtbl_addr = UT64_MAX;
	spec->vtbl_addr = UT64_MAX;
	spec->base      = 0;
	spec->defjump   = UT64_MAX;
	spec->ncases    = 0;
	spec->esize     = 4;
	spec->vsize     = 0;
	spec->shift     = 0;
	spec->lowcase   = 0;
	spec->reg       = NULL;
	spec->flags     = 0;
}

R_API void r_anal_switch_spec_legacy(RAnalSwitchSpec *spec, ut64 startea,
		ut64 tbladdr, ut64 esize, ut64 ncases, ut64 base) {
	R_RETURN_IF_FAIL (spec);
	r_anal_switch_spec_init (spec);
	spec->startea   = startea;
	spec->jtbl_addr = tbladdr;
	spec->esize     = esize ? (ut8)esize : 4;
	spec->ncases    = (ut32)ncases;
	if (base) {
		spec->base = base;
		spec->flags |= R_ANAL_SWITCH_F_BASE;
	}
}
