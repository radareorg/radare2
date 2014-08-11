#include <r_anal.h>


RAnalSwitchOp *switch_op_new() {
	RAnalSwitchOp * swop = R_NEW0 (RAnalSwitchOp);
	swop->cases = r_list_new ();
	swop->cases->free = (void *)free;
	swop->min_val = swop->def_val = swop->max_val = 0;
	return swop;
}

R_API RAnalSwitchOp * r_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 def_val) {
	RAnalSwitchOp *swop = switch_op_new();
	if (swop) {
		swop->addr = addr;
		swop->min_val = min_val;
		swop->def_val = min_val;
		swop->max_val = min_val;
	}
	return swop;
}

R_API void r_anal_switch_op_free(RAnalSwitchOp * swop) {
	if (swop == NULL) return;
	if (swop->cases)
		r_list_free(swop->cases);
	free(swop);
}

R_API RAnalCaseOp* r_anal_switch_op_add_case(RAnalSwitchOp * swop, ut64 addr, ut64 value, ut64 jump) {
	RAnalCaseOp * caseop = R_NEW0(RAnalCaseOp);
	caseop->addr = addr;
	caseop->value = value;
	caseop->jump = jump;
	r_list_append(swop->cases, caseop);
	return caseop;
}


