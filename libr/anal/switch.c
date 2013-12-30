#include <r_anal.h>


R_API RAnalSwitchOp *r_anal_switch_op_new() {
    RAnalSwitchOp * swop = R_NEW0 (RAnalSwitchOp);
    swop->cases = r_list_new ();
    swop->cases->free = (void *)free;
    return swop;
}

R_API RAnalSwitchOp *r_anal_switch_op_init(ut64 addr, ut64 min_val, ut64 max_val) {
    RAnalSwitchOp * swop = r_anal_switch_op_new();
    swop->addr = addr;
    swop->min_val = min_val;
    swop->max_val = max_val;
    return swop;
}

R_API void r_anal_switch_op_free(RAnalSwitchOp * swop) {
    if (swop == NULL) return;
    if (swop->cases)
        r_list_free(swop->cases);
    free(swop);
}

R_API RAnalCaseOp* r_anal_add_switch_op_case(RAnalSwitchOp * swop, ut64 addr, ut64 jump, ut64 value) {

    RAnalCaseOp * caseop = R_NEW0(RAnalCaseOp);
    caseop->addr = addr;
    caseop->value = value;
    caseop->cond = jump;
    r_list_append(swop->cases, caseop);
    return caseop;

}


