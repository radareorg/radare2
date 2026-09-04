/* Capture limits radare2 still enforces on its own type budget.
 *
 * The snapshot this file used to describe now lives in the r2sleigh
 * plugin; what stays is the bound radare2 checks for itself. */

#ifndef R2_ANAL_FUNCTION_SNAPSHOT_H
#define R2_ANAL_FUNCTION_SNAPSHOT_H

#include <r_anal.h>

#define R_ANAL_FUNCTION_SNAPSHOT_LIMITS_VERSION 4
typedef struct r_anal_function_snapshot_limits_t {
	ut32 struct_size;
	ut32 reserved;
	size_t max_base_types;
	size_t max_base_type_children;
	size_t max_base_type_string_bytes;
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

#endif
