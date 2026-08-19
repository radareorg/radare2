/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_ANAL_FUNCTION_SNAPSHOT_H
#define R2_ANAL_FUNCTION_SNAPSHOT_H

#include <r_anal.h>

// Inclusive limits for owned data collected into a function snapshot.
// String/JSON byte limits include each terminating NUL byte.
#define R_ANAL_FUNCTION_SNAPSHOT_LIMITS_VERSION 3
typedef struct r_anal_function_snapshot_limits_t {
	ut32 struct_size;
	ut32 reserved;
	size_t max_base_types;
	size_t max_base_type_children;
	size_t max_base_type_string_bytes;
	size_t max_assumptions_json_bytes;
	size_t max_function_blocks;
	size_t max_block_source_bytes;
	size_t max_function_source_bytes;
	size_t max_function_successors;
	size_t max_context_items;
	size_t max_context_string_bytes;
	size_t max_interface_parameters;
	size_t max_call_sites;
	size_t max_call_site_parameters;
	size_t max_total_call_site_parameters;
	size_t max_interface_string_bytes;
	size_t max_type_graph_types;
	size_t max_type_graph_aggregates;
	size_t max_type_graph_members;
	size_t max_total_owned_bytes;
} RAnalFunctionSnapshotLimits;

struct r_anal_function_snapshot_t {
	ut32 schema_version;
	ut32 struct_size;
	ut64 capabilities;
	RAnalFcnContext context;
	ut64 function_addr;
	ut64 function_size;
	int bits;
	ut32 endian;
	st64 maxstack;
	char *arch_id;
	char *cpu_id;
	char *function_name;
	RList *base_types; // RList<RAnalBaseType *>
	ut64 type_context_hash;
	RAnalFunctionInterfaceSnapshot function_interface;
	RAnalSnapshotReturnMechanismView return_mechanism;
	RAnalSnapshotRegisterStorage frame_pointer_storage;
	RAnalSnapshotStackAllocationContractView stack_allocation_contract;
	RAnalCallSiteInterfaceSnapshot *call_site_interfaces;
	size_t num_call_site_interfaces;
	ut64 revision_identity;
	RAnalSnapshotTypeGraph type_graph;
	RAnalFunctionImageSnapshot image;
	// Snapshots of the functions this one calls directly, collected in the same
	// locked transaction so the set describes one state of the analysis rather
	// than several. Bounded and one level deep: a consumer that reasons across a
	// call needs the callee's body, not the whole program.
	RAnalFunctionSnapshot **callee_snapshots;
	size_t num_callee_snapshots;
};

R_IPI RAnalFunctionSnapshot *r_anal_function_snapshot_collect_with_limits(RAnal *anal, RAnalFunction *fcn, const RAnalFunctionSnapshotLimits *limits, const char **reason);
R_IPI RAnalFunctionSnapshot *r_anal_function_snapshot_collect_bounded(RAnal *anal, RAnalFunction *fcn, const char **reason);
R_IPI void r_anal_function_snapshot_limits_default(R_OUT RAnalFunctionSnapshotLimits *limits);
R_IPI void r_anal_function_snapshot_free(RAnalFunctionSnapshot *snapshot);

#endif
