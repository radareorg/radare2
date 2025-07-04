#ifndef R_TREE_H
#define R_TREE_H

#include <r_list.h>
#include <r_util/r_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

struct r_tree_t;

typedef struct r_tree_node_t {
	struct r_tree_node_t *parent;
	struct r_tree_t *tree;
	RList *children; // <RTreeNode>
	unsigned int n_children;
	int depth;
	RListFree free;
	void *data;
} RTreeNode;

typedef struct r_tree_t {
	RTreeNode *root;
} RTree;

typedef struct r_tree_visitor_t {
	void (*pre_visit)(RTreeNode *, struct r_tree_visitor_t *);
	void (*post_visit)(RTreeNode *, struct r_tree_visitor_t *);
	void (*discover_child)(RTreeNode *, struct r_tree_visitor_t *);
	void *data;
	void *user;
} RTreeVisitor;
typedef void (*RTreeNodeVisitCb)(RTreeNode *n, RTreeVisitor *vis);

R_API RTree *r_tree_new(void);
R_API RTreeNode *r_tree_add_node(RTree *t, RTreeNode *node, void *child_data);
R_API void r_tree_reset(RTree *t);
R_API void r_tree_free(RTree *t);
R_API void r_tree_dfs(RTree *t, RTreeVisitor *vis);
R_API void r_tree_bfs(RTree *t, RTreeVisitor *vis);

#ifdef __cplusplus
}
#endif

#endif //  R_TREE_H
