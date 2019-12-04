/* radare2 - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_util/r_intervaltree.h>

#define unwrap(rbnode) container_of (rbnode, RIntervalNode, node)

static void node_max(RBNode *node) {
	RIntervalNode *intervalnode = unwrap (node);
	intervalnode->max_end = intervalnode->end;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap (node->child[i])->max_end;
			if (end > intervalnode->max_end) {
				intervalnode->max_end = end;
			}
		}
	}
}

static int cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_start = *(ut64 *)incoming;
	ut64 other_start = container_of (in_tree, const RIntervalNode, node)->start;
	if(incoming_start < other_start)
		return -1;
	if(incoming_start > other_start)
		return 1;
	return 0;
}

R_API void r_interval_tree_init(RIntervalTree *tree, RIntervalNodeFree free) {
	tree->root = NULL;
	tree->free = free;
}

static void interval_node_free(RBNode *node, void *user) {
	RIntervalNode *ragenode /* >:-O */ = unwrap (node);
	if (user) {
		((RContRBFree)user) (ragenode->data);
	}
	free (ragenode);
}

R_API void r_interval_tree_fini(RIntervalTree *tree) {
	if (!tree || !tree->root) {
		return;
	}
	r_rbtree_free (&tree->root->node, interval_node_free, tree->free);
}

R_API bool r_interval_tree_insert(RIntervalTree *tree, ut64 start, ut64 end, void *data) {
	RIntervalNode *node = R_NEW0 (RIntervalNode);
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
// Otherwise r_interval_node_all_at will break.
R_API RIntervalNode *r_interval_tree_node_at(RIntervalTree *tree, ut64 start) {
	RIntervalNode *node = tree->root;
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

R_API void r_interval_tree_all_at(RIntervalTree *tree, ut64 start, RIntervalIterCb cb, void *user) {
	// Find the topmost node matching start so we have a sub-tree with all entries that we want to find.
	RIntervalNode *top_intervalnode = r_interval_tree_node_at (tree, start);
	if (!top_intervalnode) {
		return;
	}

	// If there are more nodes with the same key, they can be in both children.
	// Start with the leftmost child that matches start and iterate from there
	RBIter it;
	it.len = 0;
	RBNode *node;
	for (node = &top_intervalnode->node; node && unwrap (node->child[0])->start == start; node = node->child[0]) {
		it.path[it.len++] = node;
	}
	while (r_rbtree_iter_has (&it)) {
		RIntervalNode *intervalnode = r_rbtree_iter_get (&it, RIntervalNode, node);
		if (intervalnode->start != start) {
			break;
		}
		cb (intervalnode, user);
	}
}

R_API void r_interval_node_all_in(RIntervalNode *node, ut64 value, bool end_inclusive, RIntervalIterCb cb, void *user) {
	while (node && value < node->start) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->node.child[0]);
	}
	if (!node) {
		return;
	}
	if (end_inclusive ? value > node->max_end : value >= node->max_end) {
		return;
	}
	if (end_inclusive ? value <= node->end : value < node->end) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	r_interval_node_all_in (unwrap (node->node.child[0]), value, end_inclusive, cb, user);
	r_interval_node_all_in (unwrap (node->node.child[1]), value, end_inclusive, cb, user);
}

R_API void r_interval_tree_all_in(RIntervalTree *tree, ut64 value, bool end_inclusive, RIntervalIterCb cb, void *user) {
	// all in! 🂡
	r_interval_node_all_in (tree->root, value, end_inclusive, cb, user);
}

static void r_interval_node_all_intersect(RIntervalNode *node, ut64 start, ut64 end, bool end_inclusive, RIntervalIterCb cb, void *user) {
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
	if (end_inclusive ? start <= node->end : start < node->end) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	r_interval_node_all_intersect (unwrap (node->node.child[0]), start, end, end_inclusive, cb, user);
	r_interval_node_all_intersect (unwrap (node->node.child[1]), start, end, end_inclusive, cb, user);
}

R_API void r_interval_tree_all_intersect(RIntervalTree *tree, ut64 start, ut64 end, bool end_inclusive, RIntervalIterCb cb, void *user) {
	r_interval_node_all_intersect (tree->root, start, end, end_inclusive, cb, user);
}