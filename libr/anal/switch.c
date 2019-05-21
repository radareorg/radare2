/* radare - LGPL - Copyright 2014-2019 - pancake, dso */

#include <r_anal.h>

static RAnalSwitchOp *__switch_op_new() {
	RAnalSwitchOp * swop = R_NEW0 (RAnalSwitchOp);
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

R_API RAnalSwitchOp * r_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 def_val) {
	RAnalSwitchOp *swop = __switch_op_new ();
	if (swop) {
		swop->addr = addr;
		swop->min_val = min_val;
		swop->def_val = min_val;
		swop->max_val = min_val;
	}
	return swop;
}

R_API RAnalCaseOp * r_anal_case_op_new(ut64 addr, ut64 val, ut64 jump) {
	RAnalCaseOp *c = R_NEW0 (RAnalCaseOp);
	if (c) {
		c->addr = addr;
		c->value = val;
		c->jump = jump;
	}
	return c;
}

R_API void r_anal_switch_op_free(RAnalSwitchOp * swop) {
	if (swop) {
		r_list_free (swop->cases);
		free (swop);
	}
}

R_API RAnalCaseOp* r_anal_switch_op_add_case(RAnalSwitchOp * swop, ut64 addr, ut64 value, ut64 jump) {
	r_return_val_if_fail (swop && addr != UT64_MAX, NULL);
	RAnalCaseOp * caseop = r_anal_case_op_new (addr, value, jump);
	if (caseop) {
		r_list_append (swop->cases, caseop);
	}
	return caseop;
}
