#ifndef R2_GRAPH_DRAWABLE_H
#define R2_GRAPH_DRAWABLE_H

#include <r_types.h>
#include <r_util/r_graph.h>
#include <r_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generic drawable graph node.
 */
typedef struct r_anal_graph_node_info_t {
	char *title;
	char *body;
	ut64 offset;
} RGraphNodeInfo;

R_API void r_graph_free_node_info(void *ptr);
R_API RGraphNodeInfo *r_graph_create_node_info(const char *title, const char *body, ut64 offset);
R_API RGraphNode *r_graph_add_node_info(RGraph *graph, const char *title, const char *body, ut64 offset);

R_API char *r_graph_drawable_to_dot(RGraph /*RGraphNodeInfo*/ *graph, const char *node_properties, const char *edge_properties);
R_API void r_graph_drawable_to_json(RGraph /*RGraphNodeInfo*/ *graph, PJ *pj, bool use_offset);

#ifdef __cplusplus
}
#endif
#endif
