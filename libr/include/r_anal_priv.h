/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_ANAL_PRIV_H
#define R2_ANAL_PRIV_H

#include "r_anal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_anal_priv_t {
	bool types_dirty;
	int types_loaded_bits;
	char *dir_prefix;
} RAnalPriv;

// Recorded adrp/add (or lea) target for a register. Populated by the
// function recurser as it walks a basic block and consumed by the jmptbl
// dispatcher resolver.
typedef struct r_leaddr_pair_t {
	ut64 op_addr;
	ut64 leaddr;
	char *reg;
} RLeaddrPair;

#define R_ANAL_PRIV(x) ((RAnalPriv*)(x)->priv)
#define R_ANAL_CC_STACK_POP_UNKNOWN (-1)

/* Store a function's calling convention, resolving a bare dyncc marker. */
R_IPI bool r_anal_var_is_default_argname(const char *name);
/* Adopt the block a switch case targets. False when no block covers it, in
 * which case the case needs scanning; the walker decides where. */
R_IPI bool r_anal_function_materialize_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr);
/* Scan a switch case outside a walk and adopt the block it produced. */
R_IPI void r_anal_function_scan_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr);
typedef struct r_anal_switch_cursor_t RAnalSwitchCursor;
/* Apply cases until one needs scanning: true with `*target` set. False once the
 * table is finished, after which only r_anal_switch_cursor_finish may follow. */
R_IPI bool r_anal_switch_cursor_step(RAnalSwitchCursor *c, ut64 *target);
/* Record the switch the cases applied so far describe, and free the cursor. */
R_IPI void r_anal_switch_cursor_finish(RAnalSwitchCursor *c);
R_IPI int r_anal_cc_stack_pop(RAnal *anal, const char *convention);
R_IPI int r_anal_cc_shadow(RAnal *anal, const char *convention);
R_IPI bool r_anal_cc_stack_rev(RAnal *anal, const char *cc);
R_IPI int r_anal_cc_raslot(RAnal *anal, int word);
R_IPI const char *r_anal_cc_rolelabel(char tag, char label[2], int *slot);
R_IPI bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all);
R_IPI const char *r_anal_call_type_at(RAnal *anal, ut64 addr);
R_IPI void r_anal_call_type_set(RAnal *anal, ut64 addr, const char *type);

// Bump the recorded leaddr of the most recent entry that matches `reg` by
// `delta`. Used on arm64 to finalise `adrp Rd, page; add Rd, Rd, #imm`
// sequences where multiple adrp's can interleave before their matching adds.
R_IPI void r_anal_jmptbl_leaddrs_bump(RList *leaddrs, const char *reg, ut64 delta);

// Detect and walk an arm64 jmptbl dispatcher at the indirect branch `op`.
// Scans the preceding add/load pair, resolves the base/table lea pairs
// via the recorded `leaddrs`, reads the table and registers each case.
// Returns true when a jmptbl was successfully resolved and applied.
R_IPI bool r_anal_jmptbl_arm64_from_br(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, RAnalOp *op, int loadsize, const RAnalScanSink *sink);

#ifdef __cplusplus
}
#endif

#endif
