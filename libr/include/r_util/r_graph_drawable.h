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
 * 
 * Provides minimal information to draw something without output format specific details.
 */
typedef struct r_anal_graph_node_info_t {
	char *title;
	char *body;
	/**
	 * @brief Optional offset for the object corresponding to node.
	 * 
	 * Interactive output modes can use it to provide actions like seeking to
	 * this position or modify the object.
	 */
	ut64 offset;
} RGraphNodeInfo;

R_API void r_graph_free_node_info(void *ptr);
R_API RGraphNodeInfo *r_graph_create_node_info(const char *title, const char *body, ut64 offset);
R_API RGraphNode *r_graph_add_node_info(RGraph *graph, const char *title, const char *body, ut64 offset);

/**
 * @brief Convert graph to Graphviz dot format.
 * 
 * @param graph Graph with RGraphNodeInfo used as node user data
 * @param node_properties List node styling attributes. Can be set to NULL.
 * @param edge_properties List edge styling attributes. Can be set to NULL.
 */
R_API char *r_graph_drawable_to_dot(RGraph /*RGraphNodeInfo*/ *graph, const char *node_properties, const char *edge_properties);
/**
 * @brief Convert graph to JSON.
 * 
 * @param[in] graph Graph to convert
 * @param[out] pj Json output structure. Can be used to include the resulting JSON value inside bigger JSON.
 * @param[in] use_offset Set this to true if graph uses \ref RGraphNodeInfo::offset offset field.
 */
R_API void r_graph_drawable_to_json(RGraph /*RGraphNodeInfo*/ *graph, PJ *pj, bool use_offset);

#ifdef __cplusplus
}
#endif
#endif
