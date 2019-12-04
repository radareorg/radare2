/* radare2 - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R_INTERVALTREE_H
#define R_INTERVALTREE_H

#include "r_rbtree.h"
#include "../r_types.h"

/*
 * RIntervalTree is a special RBTree (augmented red-black tree)
 * that holds its entries, each associated with a interval,
 * ordered by the start of the interval.
 *
 * It allows efficient lookup for intersections with a given interval or value.
 * This is achieved by, at each node, saving the maximum value of the node
 * and all of its children.
 *
 * It can hold multiple entries with the same start or end.
 * For multiple entries with the same start, the ordering is undefined.
 */

typedef struct r_interval_node_t {
	RBNode node;
	ut64 start; // inclusive, key of the node
	ut64 end; // may be inclusive or exclusive, this is only determined by how they are queried
	ut64 max_end; // augmented value, maximum end of this node and all of its children
	void *data;
} RIntervalNode;

typedef void (*RIntervalNodeFree)(void *data);

typedef struct r_interval_tree_t {
	RIntervalNode *root;
	RIntervalNodeFree free;
} RIntervalTree;

R_API void r_interval_tree_init(RIntervalTree *tree, RIntervalNodeFree free);
R_API void r_interval_tree_fini(RIntervalTree *tree);
R_API bool r_interval_tree_insert(RIntervalTree *tree, ut64 start, ut64 end, void *data);

// Returns a node that starts at exactly start or NULL
R_API RIntervalNode *r_interval_tree_node_at(RIntervalTree *tree, ut64 start);

// Same as r_interval_tree_node_at, but directly returns the contained value or NULL
static inline void *r_interval_tree_at(RIntervalTree *tree, ut64 start) {
	RIntervalNode *node = r_interval_tree_node_at (tree, start);
	return node ? node->data : NULL;
}

typedef void (*RIntervalIterCb)(RIntervalNode *node, void *user);

// Call cb for all entries starting at exactly start
R_API void r_interval_tree_all_at(RIntervalTree *tree, ut64 start, RIntervalIterCb cb, void *user);

// Call cb for all entries whose intervals contain value
R_API void r_interval_tree_all_in(RIntervalTree *tree, ut64 value, bool end_inclusive, RIntervalIterCb cb, void *user);

// Call cb for all entries whose intervals intersect the given interval (might not contain it completely)
R_API void r_interval_tree_all_intersect(RIntervalTree *tree, ut64 start, ut64 end, bool end_inclusive, RIntervalIterCb cb, void *user);

#define r_interval_tree_foreach(tree, it, dat) \
	for ((it) = r_rbtree_first (&tree->root->node); r_rbtree_iter_has(&it) && (dat = r_rbtree_iter_get (&it, RIntervalNode, node)->data); r_rbtree_iter_next (&(it)))

#define r_interval_tree_foreach_prev(tree, it, dat) \
	for ((it) = r_rbtree_last (&tree->root->node); r_rbtree_iter_has(&it) && (dat = r_rbtree_iter_get (&it, RIntervalNode, node)->data); r_rbtree_iter_prev (&(it)))


#endif //R_INTERVALTREE_H
