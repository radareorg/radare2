#ifndef R_GRAPH_H
#define R_GRAPH_H

#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_graph_node_t {
	unsigned int idx;
	void *data;
	RList *out_nodes;
	RList *in_nodes;
	RList *all_neighbours;
	RListFree free;
} RGraphNode;

typedef struct r_graph_edge_t {
	RGraphNode *from;
	RGraphNode *to;
	int nth;
} RGraphEdge;

typedef struct r_graph_t {
	unsigned int n_nodes;
	unsigned int n_edges;
	int last_index;
	RList *nodes; /* RGraphNode */
} RGraph;

typedef struct r_graph_visitor_t {
	void (*discover_node)(RGraphNode *n, struct r_graph_visitor_t *vis);
	void (*finish_node)(RGraphNode *n, struct r_graph_visitor_t *vis);
	void (*tree_edge)(const RGraphEdge *e, struct r_graph_visitor_t *vis);
	void (*back_edge)(const RGraphEdge *e, struct r_graph_visitor_t *vis);
	void (*fcross_edge)(const RGraphEdge *e, struct r_graph_visitor_t *vis);
	void *data;
} RGraphVisitor;
typedef void (*RGraphNodeCallback)(RGraphNode *n, RGraphVisitor *vis);
typedef void (*RGraphEdgeCallback)(const RGraphEdge *e, RGraphVisitor *vis);

// Contrructs a new RGraph, returns heap-allocated graph.
R_API RGraph *r_graph_new(void);
// Destroys the graph and all nodes.
R_API void r_graph_free(RGraph* g);
// Gets the data of a node by index.
R_API RGraphNode *r_graph_get_node(const RGraph *g, unsigned int idx);
R_API RListIter *r_graph_node_iter(const RGraph *g, unsigned int idx);
R_API void r_graph_reset(RGraph *g);
R_API RGraphNode *r_graph_add_node(RGraph *g, void *data);
R_API RGraphNode *r_graph_add_nodef(RGraph *g, void *data, RListFree user_free);
// XXX 'n' is destroyed after calling this function.
R_API void r_graph_del_node(RGraph *g, RGraphNode *n);
R_API void r_graph_add_edge(RGraph *g, RGraphNode *from, RGraphNode *to);
R_API void r_graph_add_edge_at(RGraph *g, RGraphNode *from, RGraphNode *to, int nth);
R_API RGraphNode *r_graph_node_split_forward(RGraph *g, RGraphNode *split_me, void *data);
R_API void r_graph_del_edge(RGraph *g, RGraphNode *from, RGraphNode *to);
R_API const RList *r_graph_get_neighbours(const RGraph *g, const RGraphNode *n);
R_API RGraphNode *r_graph_nth_neighbour(const RGraph *g, const RGraphNode *n, int nth);
R_API const RList *r_graph_innodes(const RGraph *g, const RGraphNode *n);
R_API const RList *r_graph_all_neighbours(const RGraph *g, const RGraphNode *n);
R_API const RList *r_graph_get_nodes(const RGraph *g);
R_API bool r_graph_adjacent(const RGraph *g, const RGraphNode *from, const RGraphNode *to);
R_API void r_graph_dfs_node(RGraph *g, RGraphNode *n, RGraphVisitor *vis);
R_API void r_graph_dfs_node_reverse(RGraph *g, RGraphNode *n, RGraphVisitor *vis);
R_API void r_graph_dfs(RGraph *g, RGraphVisitor *vis);

#ifdef __cplusplus
}
#endif

#endif //  R_GRAPH_H
