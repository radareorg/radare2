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
	HtUP *exact_formal_proofs; // RAnalVar * => RAnalExactFormalProof *
	HtUP *dwarf_exact_formal_records; // function address => HtUP<arg index, RAnalDwarfExactFormalRecord *>
	HtUP *dwarf_function_link_authority; // function address => RAnalDwarfFunctionLinkAuthority *
	HtUP *dwarf_frame_pointer_proofs; // function address => RAnalDwarfFramePointerProof *
	ut64 dwarf_function_link_generation;
} RAnalPriv;

typedef struct r_anal_exact_formal_proof_t {
	RAnalFunction *fcn;
	ut64 function_addr;
	int ordinal;
	RAnalVarKind kind;
	int delta;
	st64 source_offset;
	st64 bp_off;
	int maxstack;
	char *type;
} RAnalExactFormalProof;

typedef struct r_anal_dwarf_exact_formal_record_t {
	int arg_index;
	char *serialized;
} RAnalDwarfExactFormalRecord;

typedef enum {
	R_ANAL_DWARF_FUNCTION_LINK_POISONED = 0,
	R_ANAL_DWARF_FUNCTION_LINK_OWNED,
} RAnalDwarfFunctionLinkState;

typedef struct r_anal_dwarf_function_link_authority_t {
	char *type_name;
	ut64 generation;
	RAnalDwarfFunctionLinkState state;
} RAnalDwarfFunctionLinkAuthority;

typedef struct r_anal_dwarf_frame_pointer_proof_t {
	char *type_name;
	char *arch;
	char *reg_name;
	ut64 generation;
	ut64 offset;
	ut32 size;
	int dwarf_reg_num;
	int bits;
} RAnalDwarfFramePointerProof;

typedef struct r_anal_dwarf_frame_pointer_storage_t {
	char *name;
	ut64 offset;
	ut32 size;
} RAnalDwarfFramePointerStorage;

typedef struct r_anal_function_snapshot_limits_t RAnalFunctionSnapshotLimits;
typedef struct r_anal_meta_store_shadow_t RAnalMetaStoreShadow;
typedef struct r_anal_owned_xref_prepared_t RAnalOwnedXrefPrepared;

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

R_IPI RAnalFunctionSnapshot *r_anal_function_snapshot_collect_bounded(RAnal *anal, RAnalFunction *fcn, const char **reason);
R_IPI void r_anal_function_snapshot_free(RAnalFunctionSnapshot *snapshot);
// Internal cross-library bridge. It provides bounded immutable data only; it
// does not establish core-lock, IO-trust, CFG, or semantic authority.
R_API bool r_anal_function_snapshot_visit_bounded_advisory(RAnal *anal, ut64 function_addr, RAnalFunctionSnapshotCallback callback, void *user, const char **reason);
R_API R_OWNED RVecAnalRef *r_anal_refs_get_unowned(RAnal *anal, ut64 from);
// Returns an owned RList<RAnalPluginDataRefsBatch *>; r_list_free releases it.
R_API bool r_anal_plugin_data_refs_collect(RAnal *anal, RAnalFunction *fcn, R_OUT RList **batches);
// Internal cross-library transaction bridge. The caller must hold anal->lock
// continuously across prepare, coordinated swaps, and publish. Swap is
// reversible until publish; prepared_free may run after releasing the lock.
R_API RAnalOwnedXrefStatus r_anal_xrefs_owned_prepare_many(RAnal *anal, const RAnalOwnedXrefSet *sets, size_t set_count, R_OUT RAnalOwnedXrefPrepared **prepared);
R_API bool r_anal_xrefs_owned_changed(const RAnalOwnedXrefPrepared *prepared);
R_API void r_anal_xrefs_owned_swap(RAnal *anal, RAnalOwnedXrefPrepared *prepared);
R_API void r_anal_xrefs_owned_publish(RAnal *anal, const RAnalOwnedXrefPrepared *prepared);
R_API void r_anal_xrefs_owned_prepared_free(RAnalOwnedXrefPrepared *prepared);
// Caller-held anal->lock required. Clears every owned contribution atomically,
// preserving the complete unowned/legacy projection.
R_API RAnalOwnedXrefStatus r_anal_xrefs_owned_clear_all(RAnal *anal);

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
R_IPI ut64 r_anal_types_context_hash_from_snapshot(RAnal *anal, const RList *types, ut64 type_dirty_epoch);
R_IPI const char *r_anal_function_type_link_at(RAnal *anal, ut64 addr);
R_IPI bool r_anal_function_type_link_set(RAnal *anal, const char *type_name, ut64 addr);
R_IPI bool r_anal_function_type_link_set_owned(RAnal *anal, const char *type_name, ut64 addr);
R_IPI bool r_anal_var_is_default_argname(const char *name);
R_IPI bool r_anal_var_exact_formal_set(RAnal *anal, RAnalVar *var, ut64 function_addr, int ordinal, RAnalVarKind kind, int delta, st64 source_offset, const char *type);
R_IPI bool r_anal_var_exact_formal_get(RAnal *anal, const RAnalVar *var, R_OUT int *ordinal);
R_IPI void r_anal_var_exact_formal_clear(RAnal *anal, const RAnalVar *var);
R_IPI HtUP *r_anal_dwarf_exact_formal_records_new(void);
R_IPI void r_anal_dwarf_exact_formal_records_free(HtUP *records);
R_IPI bool r_anal_dwarf_exact_formal_record_add(HtUP *records, ut64 function_addr, int arg_index, const char *serialized);
R_IPI bool r_anal_dwarf_exact_formal_record_matches(const RAnal *anal, ut64 function_addr, int arg_index, const char *serialized);
R_IPI void r_anal_dwarf_exact_formal_records_publish(RAnal *anal, HtUP *records);
R_IPI void r_anal_dwarf_exact_formal_authority_reset(RAnal *anal);
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
R_IPI bool r_anal_dwarf_function_link_is_current(const RAnal *anal, ut64 function_addr, const char *type_name);
R_IPI void r_anal_dwarf_function_link_authority_clear(RAnal *anal);
R_IPI HtUP *r_anal_dwarf_frame_pointer_proofs_new(void);
R_IPI void r_anal_dwarf_frame_pointer_proofs_free(HtUP *proofs);
R_IPI bool r_anal_dwarf_frame_pointer_proof_add(HtUP *proofs, ut64 function_addr, const char *type_name, const char *arch, int bits, int dwarf_reg_num, const char *reg_name, ut64 offset, ut32 size);
R_IPI bool r_anal_dwarf_frame_pointer_proofs_publish(RAnal *anal, HtUP *proofs);
R_IPI bool r_anal_dwarf_frame_pointer_proofs_rebind_current(RAnal *anal);
R_IPI bool r_anal_dwarf_function_frame_pointer_get(const RAnal *anal, ut64 function_addr, R_OUT RAnalDwarfFramePointerStorage *storage);
R_IPI void r_anal_dwarf_frame_pointer_storage_fini(RAnalDwarfFramePointerStorage *storage);
R_IPI void r_anal_function_vars_cache_init_readonly(RAnal *anal, RAnalFcnVarsCache *cache, RAnalFunction *fcn);
R_IPI bool r_anal_function_has_address_linked_signature_current(RAnalFunction *function);
R_IPI bool r_anal_function_materialize_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr, int depth);
R_API RAnalMetaStoreShadow *r_meta_store_shadow_prepare(RAnal *anal);
R_API const char *r_meta_get_string_in_space(RAnal *anal, RAnalMetaType type, const RSpace *space, ut64 addr);
R_API bool r_meta_store_shadow_set_comment(RAnalMetaStoreShadow *shadow, const RSpace *space, ut64 addr, const char *text);
R_API void r_meta_store_shadow_del_comment(RAnalMetaStoreShadow *shadow, const RSpace *space, ut64 addr);
R_API void r_meta_store_shadow_swap(RAnal *anal, RAnalMetaStoreShadow *shadow);
R_API void r_meta_store_shadow_free(RAnalMetaStoreShadow *shadow);
R_IPI int r_anal_cc_stack_pop(RAnal *anal, const char *convention);
R_IPI int r_anal_cc_shadow(RAnal *anal, const char *convention);
R_IPI bool r_anal_cc_stack_rev(RAnal *anal, const char *cc);
R_IPI int r_anal_cc_raslot(RAnal *anal, int word);
R_IPI bool r_anal_cc_return_mechanism(RAnal *anal, const char *convention, R_OUT RAnalCCReturnMechanism *mechanism);
R_IPI bool r_anal_cc_stack_allocation_contract(RAnal *anal, const char *convention, R_OUT RAnalCCStackAllocationContract *contract);
R_IPI const char *r_anal_cc_rolelabel(char tag, char label[2], int *slot);
R_IPI bool r_anal_cc_location_uses(RAnal *anal, const char *loc, const char *reg);
R_IPI bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all);
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
