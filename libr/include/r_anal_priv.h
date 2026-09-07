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
	HtUP *dwarf_function_link_authority; // function address => RAnalDwarfFunctionLinkAuthority *
	ut64 dwarf_function_link_generation;
} RAnalPriv;

typedef enum {
	R_ANAL_DWARF_FUNCTION_LINK_POISONED = 0,
	R_ANAL_DWARF_FUNCTION_LINK_OWNED,
} RAnalDwarfFunctionLinkState;

typedef struct r_anal_dwarf_function_link_authority_t {
	char *type_name;
	ut64 generation;
	RAnalDwarfFunctionLinkState state;
} RAnalDwarfFunctionLinkAuthority;

typedef struct r_anal_function_snapshot_limits_t RAnalFunctionSnapshotLimits;

typedef struct r_anal_plugin_data_refs_batch_t {
	char *provider_id; // Owned by the batch list.
	bool success; // True makes refs authoritative; false preserves prior output.
	RVecAnalRef *refs; // Owned by the batch list; NULL is authoritative empty on success.
} RAnalPluginDataRefsBatch;

typedef enum {
	R_ANAL_CC_RETURN_MECHANISM_NONE = 0,
	R_ANAL_CC_RETURN_MECHANISM_STACK,
} RAnalCCReturnMechanismKind;

typedef struct r_anal_cc_return_mechanism_t {
	RAnalCCReturnMechanismKind kind;
	st64 entry_sp_offset;
	ut32 slot_size;
	st64 exit_sp_delta;
} RAnalCCReturnMechanism;

typedef enum {
	R_ANAL_CC_STACK_GROWTH_NONE = 0,
	R_ANAL_CC_STACK_GROWTH_LOWER,
	R_ANAL_CC_STACK_GROWTH_HIGHER,
} RAnalCCStackGrowth;

typedef struct r_anal_cc_stack_allocation_contract_t {
	// A full-width SP move in this direction grants the callee exclusive use
	// of the half-open interval between the entry and moved SP until exact
	// restoration. The red zone is the exact convention-owned interval that is
	// available without moving SP.
	RAnalCCStackGrowth growth;
	ut32 red_zone_bytes;
} RAnalCCStackAllocationContract;

// Returns an owned RList<RAnalPluginDataRefsBatch *>; r_list_free releases it.
R_API bool r_anal_plugin_data_refs_collect(RAnal *anal, RAnalFunction *fcn, R_OUT RList **batches);

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

R_IPI void r_anal_types_ensure_loaded(RAnal *anal);
R_IPI RList *r_anal_types_snapshot_with_limits(RAnal *anal, const RAnalFunctionSnapshotLimits *limits);
R_IPI const char *r_anal_function_type_link_at(RAnal *anal, ut64 addr);
R_IPI bool r_anal_function_type_link_set(RAnal *anal, const char *type_name, ut64 addr);
R_IPI bool r_anal_function_type_link_set_owned(RAnal *anal, const char *type_name, ut64 addr);
R_IPI bool r_anal_var_is_default_argname(const char *name);
// A reset logically poisons every previously owned link in O(1). The parser
// must prepare an exact address/type with mark_poisoned before changing the
// live fcnlink, then publish_owned only after the complete generation commits.
R_IPI bool r_anal_dwarf_function_link_mark_poisoned(RAnal *anal, ut64 function_addr, const char *type_name);
R_IPI bool r_anal_dwarf_function_link_poisoned_matches(const RAnal *anal, ut64 function_addr, const char *type_name);
// Resolves all prior-generation/poisoned records without mutating the private
// table during iteration. Exact owned live links are removed; absent or
// differing foreign links are preserved. Failed deletes retain poison.
R_IPI bool r_anal_dwarf_function_links_revoke_owned(RAnal *anal);
R_IPI bool r_anal_dwarf_function_link_publish_owned(RAnal *anal, ut64 function_addr, const char *type_name);
// Every non-DWARF fcnlink mutation, including an identical-value write, must
// call mark_unowned so ownership cannot survive a user replacement.
R_IPI void r_anal_dwarf_function_link_mark_unowned(RAnal *anal, ut64 function_addr);
// Returns true for no private state (an ordinary user link) or an exact live
// owned match; poisoned and mismatched owned records fail closed.
R_IPI void r_anal_dwarf_function_link_authority_clear(RAnal *anal);
R_IPI void r_anal_function_vars_cache_init_readonly(RAnal *anal, RAnalFcnVarsCache *cache, RAnalFunction *fcn);
R_IPI bool r_anal_function_materialize_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr, int depth);
R_API const char *r_meta_get_string_in_space(RAnal *anal, RAnalMetaType type, const RSpace *space, ut64 addr);
R_IPI int r_anal_cc_stack_pop(RAnal *anal, const char *convention);
R_IPI int r_anal_cc_shadow(RAnal *anal, const char *convention);
R_IPI bool r_anal_cc_stack_rev(RAnal *anal, const char *cc);
R_IPI int r_anal_cc_raslot(RAnal *anal, int word);
R_IPI bool r_anal_cc_return_mechanism(RAnal *anal, const char *convention, R_OUT RAnalCCReturnMechanism *mechanism);
R_IPI bool r_anal_cc_stack_allocation_contract(RAnal *anal, const char *convention, R_OUT RAnalCCStackAllocationContract *contract);
R_IPI const char *r_anal_cc_rolelabel(char tag, char label[2], int *slot);
R_IPI bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all);
R_IPI const char *r_anal_call_type_at(RAnal *anal, ut64 addr);
R_IPI void r_anal_call_type_set(RAnal *anal, ut64 addr, const char *type);
R_IPI bool r_anal_cc_preserves_reg(RAnal *anal, const char *convention, const char *reg);

// Bump the recorded leaddr of the most recent entry that matches `reg` by
// `delta`. Used on arm64 to finalise `adrp Rd, page; add Rd, Rd, #imm`
// sequences where multiple adrp's can interleave before their matching adds.
R_IPI void r_anal_jmptbl_leaddrs_bump(RList *leaddrs, const char *reg, ut64 delta);

// Detect and walk an arm64 jmptbl dispatcher at the indirect branch `op`.
// Scans the preceding add/load pair, resolves the base/table lea pairs
// via the recorded `leaddrs`, reads the table and registers each case.
// Returns true when a jmptbl was successfully resolved and applied.
R_IPI bool r_anal_jmptbl_arm64_from_br(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, int depth, RAnalOp *op, int loadsize);

#ifdef __cplusplus
}
#endif

#endif
