/* radare2 - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R_RANGETREE_H
#define R_RANGETREE_H

#include "r_rbtree.h"
#include "../r_types.h"

/*
 * RRangeTree is a special RBTree (augmented red-black tree)
 * that holds its entries, each associated with a range,
 * ordered by the start of the range.
 *
 * It allows efficient lookup for intersections with a given range or value.
 * This is achieved by, at each node, saving the maximum value of the node
 * and all of its children.
 *
 * It can hold multiple entries with the same start or end.
 * For multiple entries with the same start, the ordering is undefined.
 */

typedef struct r_range_node_t {
	RBNode node;
	ut64 start; // inclusive, key of the node
	ut64 end; // may be inclusive or exclusive, this is only determined by how they are queried
	ut64 max_end; // augmented value, maximum end of this node and all of its children
	void *data;
} RRangeNode;

typedef void (*RRangeNodeFree)(void *data);

typedef struct r_range_tree_t {
	RRangeNode *root;
	RRangeNodeFree free;
} RRangeTree;

R_API void r_range_tree_init(RRangeTree *tree, RRangeNodeFree free);
R_API void r_range_tree_fini(RRangeTree *tree);
R_API bool r_range_tree_insert(RRangeTree *tree, ut64 start, ut64 end, void *data);

// Returns a node that starts at exactly start or NULL
R_API RRangeNode *r_range_tree_node_at(RRangeTree *tree, ut64 start);

// Same as r_range_tree_node_at, but directly returns the contained value or NULL
static inline void *r_range_tree_at(RRangeTree *tree, ut64 start) {
	RRangeNode *node = r_range_tree_node_at (tree, start);
	return node ? node->data : NULL;
}

typedef void (*RRangeIterCb)(RRangeNode *node, void *user);

// Call cb for all entries starting at exactly start
R_API void r_range_tree_all_at(RRangeTree *tree, ut64 start, RRangeIterCb cb, void *user);

// Call cb for all entries whose ranges contain value
R_API void r_range_tree_all_in(RRangeTree *tree, ut64 value, bool end_inclusive, RRangeIterCb cb, void *user);

// Call cb for all entries whose ranges intersect the given range (might not contain it completely)
R_API void r_range_tree_all_intersect(RRangeTree *tree, ut64 start, ut64 end, bool end_inclusive, RRangeIterCb cb, void *user);

#define r_range_tree_foreach(tree, it, dat) \
	for ((it) = r_rbtree_first (&tree->root->node); r_rbtree_iter_has(&it) && (dat = r_rbtree_iter_get (&it, RRangeNode, node)->data); r_rbtree_iter_next (&(it)))

#define r_range_tree_foreach_prev(tree, it, dat) \
	for ((it) = r_rbtree_last (&tree->root->node); r_rbtree_iter_has(&it) && (dat = r_rbtree_iter_get (&it, RRangeNode, node)->data); r_rbtree_iter_prev (&(it)))


#endif //R_RANGETREE_H
