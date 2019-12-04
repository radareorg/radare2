/* radare2 - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_util/r_rangetree.h>

#define unwrap(rbnode) container_of (rbnode, RRangeNode, node)

static void node_max(RBNode *node) {
	RRangeNode *rangenode = unwrap (node);
	rangenode->max_end = rangenode->end;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap (node->child[i])->max_end;
			if (end > rangenode->max_end) {
				rangenode->max_end = end;
			}
		}
	}
}

static int cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_start = *(ut64 *)incoming;
	ut64 other_start = container_of (in_tree, const RRangeNode, node)->start;
	if(incoming_start < other_start)
		return -1;
	if(incoming_start > other_start)
		return 1;
	return 0;
}

R_API void r_range_tree_init(RRangeTree *tree, RRangeNodeFree free) {
	tree->root = NULL;
	tree->free = free;
}

static void range_node_free(RBNode *node, void *user) {
	RRangeNode *ragenode /* >:-O */ = unwrap (node);
	if (user) {
		((RContRBFree)user) (ragenode->data);
	}
	free (ragenode);
}

R_API void r_range_tree_fini(RRangeTree *tree) {
	if (!tree || !tree->root) {
		return;
	}
	r_rbtree_free (&tree->root->node, range_node_free, tree->free);
}

R_API bool r_range_tree_insert(RRangeTree *tree, ut64 start, ut64 end, void *data) {
	RRangeNode *node = R_NEW0 (RRangeNode);
	if (!node) {
		return false;
	}
	node->start = start;
	node->end = end;
	node->data = data;
	RBNode *root = tree->root ? &tree->root->node : NULL;
	bool r = r_rbtree_aug_insert (&root, &start, &node->node, cmp, NULL, node_max);
	tree->root = unwrap (root);
	if (!r) {
		free (node);
	}
	return r;
}

// This must always return the topmost node that matches start!
// Otherwise r_range_node_all_at will break.
R_API RRangeNode *r_range_tree_node_at(RRangeTree *tree, ut64 start) {
	RRangeNode *node = tree->root;
	while (node) {
		if (start < node->start) {
			node = unwrap (node->node.child[0]);
		} else if (start > node->start) {
			node = unwrap (node->node.child[1]);
		} else {
			return node;
		}
	}
	return NULL;
}

R_API void r_range_tree_all_at(RRangeTree *tree, ut64 start, RRangeIterCb cb, void *user) {
	// Find the topmost node matching start so we have a sub-tree with all entries that we want to find.
	RRangeNode *top_rangenode = r_range_tree_node_at (tree, start);
	if (!top_rangenode) {
		return;
	}

	// If there are more nodes with the same key, they can be in both children.
	// Start with the leftmost child that matches start and iterate from there
	RBIter it;
	it.len = 0;
	RBNode *node;
	for (node = &top_rangenode->node; node && unwrap (node->child[0])->start == start; node = node->child[0]) {
		it.path[it.len++] = node;
	}
	while (r_rbtree_iter_has (&it)) {
		RRangeNode *rangenode = r_rbtree_iter_get (&it, RRangeNode, node);
		if (rangenode->start != start) {
			break;
		}
		cb (rangenode, user);
	}
}

R_API void r_range_node_all_in(RRangeNode *node, ut64 value, bool end_inclusive, RRangeIterCb cb, void *user) {
	while (node && value < node->start) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->node.child[0]);
	}
	if (!node) {
		return;
	}
	if (end_inclusive ? value >= node->max_end : value > node->max_end) {
		return;
	}
	if (end_inclusive ? value < node->end : value <= node->end) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	r_range_node_all_in (unwrap (node->node.child[0]), value, end_inclusive, cb, user);
	r_range_node_all_in (unwrap (node->node.child[1]), value, end_inclusive, cb, user);
}

R_API void r_range_tree_all_in(RRangeTree *tree, ut64 value, bool end_inclusive, RRangeIterCb cb, void *user) {
	// all in! 🂡
	r_range_node_all_in (tree->root, value, end_inclusive, cb, user);
}

static void r_range_node_all_intersect(RRangeNode *node, ut64 start, ut64 end, bool end_inclusive, RRangeIterCb cb, void *user) {
	while (node && (end_inclusive ? end < node->start : end <= node->start)) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->node.child[0]);
	}
	if (!node) {
		return;
	}
	if (end_inclusive ? start > node->max_end : start >= node->max_end) {
		return;
	}
	if (end <= node->end) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	r_range_node_all_intersect (unwrap (node->node.child[0]), start, end, end_inclusive, cb, user);
	r_range_node_all_intersect (unwrap (node->node.child[1]), start, end, end_inclusive, cb, user);
}

R_API void r_range_tree_all_intersect(RRangeTree *tree, ut64 start, ut64 end, bool end_inclusive, RRangeIterCb cb, void *user) {
	r_range_node_all_intersect (tree->root, start, end, end_inclusive, cb, user);
}