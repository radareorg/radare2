#ifndef R2_AGRAPH_H
#define R2_AGRAPH_H

#include <r_types.h>
#include <r_cons.h>
#include <r_util/r_graph.h>

typedef struct r_ascii_node_t {
	RGraphNode *gnode;
	char *title;
	char *body;
	char *color;

	int x;
	int y;
	int w;
	int h;

	int layer;
	int layer_height;
	int layer_width;
	int pos_in_layer;
	int is_dummy;
	int is_reversed;
	int klass;
	int difftype;
	bool is_mini;
} RANode;

typedef struct r_core_graph_hits_t {
	char *old_word ;
	RVector word_list;
	int word_nth;
} RAGraphHits;


#define R_AGRAPH_MODE_NORMAL 0
#define R_AGRAPH_MODE_OFFSET 1
#define R_AGRAPH_MODE_MINI 2
#define R_AGRAPH_MODE_TINY 3
#define R_AGRAPH_MODE_SUMMARY 4
#define R_AGRAPH_MODE_COMMENTS 5
#define R_AGRAPH_MODE_MAX 6

typedef void (*RANodeCallback)(RANode *n, void *user);
typedef void (*RAEdgeCallback)(RANode *from, RANode *to, void *user);

typedef struct r_ascii_graph_t {
	RConsCanvas *can;
	RGraph *graph;
	const RGraphNode *curnode;
	char *title;
	Sdb *db;
	Sdb *nodes; // Sdb with title(key)=RANode*(value)

	int layout;
	int is_instep;
	bool is_tiny;
	bool is_dis;
	int edgemode;
	int mode;
	bool is_callgraph;
	bool is_interactive;
	int zoom;
	int movspeed;
	bool hints;

	RANode *update_seek_on;
	bool need_reload_nodes;
	bool need_set_layout;
	int need_update_dim;
	int force_update_seek;

	/* events */
	RANodeCallback on_curnode_change;
	void *on_curnode_change_data;
	bool dummy; // enable the dummy nodes for better layouting
	bool show_node_titles;
	bool show_node_body;
	bool show_node_bubble;

	int x, y;
	int w, h;

	/* layout algorithm info */
	RList *back_edges;
	RList *long_edges;
	struct layer_t *layers;
	unsigned int n_layers;
	RList *dists; /* RList<struct dist_t> */
	RList *edges; /* RList<AEdge> */
	RAGraphHits ghits;
} RAGraph;

#ifdef R_API
R_API RAGraph *r_agraph_new(RConsCanvas *can);
R_API void r_agraph_free(RAGraph *g);
R_API void r_agraph_reset(RAGraph *g);
R_API void r_agraph_set_title(RAGraph *g, const char *title);
R_API RANode *r_agraph_get_first_node(const RAGraph *g);
R_API RANode *r_agraph_get_node(const RAGraph *g, const char *title);
R_API RANode *r_agraph_add_node(const RAGraph *g, const char *title, const char *body, const char *color);
R_API bool r_agraph_del_node(const RAGraph *g, const char *title);
R_API void r_agraph_add_edge(const RAGraph *g, RANode *a, RANode *b, bool highlight);
R_API void r_agraph_add_edge_at(const RAGraph *g, RANode *a, RANode *b, int nth);
R_API void r_agraph_del_edge(const RAGraph *g, RANode *a, RANode *b);
R_API void r_agraph_print(RAGraph *g);
R_API void r_agraph_print_json(RAGraph *g, PJ *pj);
R_API Sdb *r_agraph_get_sdb(RAGraph *g);
R_API void r_agraph_foreach(RAGraph *g, RANodeCallback cb, void *user);
R_API void r_agraph_foreach_edge(RAGraph *g, RAEdgeCallback cb, void *user);
R_API void r_agraph_set_curnode(RAGraph *g, RANode *node);
R_API RAGraph *create_agraph_from_graph(const RGraph/*<RGraphNodeInfo>*/ *graph);
#endif

#endif
