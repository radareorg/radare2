/*
BSD 2-Clause License

Copyright (c) 2018, lynnl

Cleaned up and refactored for r2 in 2021 - 2022: condret

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <r_util.h>

static void _set_link(RRBNode *parent, RRBNode *child, const int dir) {
	if (parent) {
		parent->link[dir] = child;
	}
	if (child) {
		child->parent = parent;
	}
}

R_API RRBTree *r_crbtree_new(RRBFree freefn) {
	RRBTree *tree = R_NEW0 (RRBTree);
	if (tree) {
		tree->free = freefn;
	}
	return tree;
}

R_API void r_crbtree_clear(RRBTree *tree) {
	r_return_if_fail (tree);
	RRBNode *iter = tree->root, *save = NULL;

	// Rotate away the left links into a linked list so that
	// we can perform iterative destruction of the rbtree
	while (iter) {
		if (!iter->link[0]) {
			save = iter->link[1];
			if (tree->free) {
				tree->free (iter->data);
			}
			free (iter);
			tree->size--;
		} else {
			save = iter->link[0];
			_set_link (iter, save->link[1], 0);
			_set_link (save, iter, 1);
		}
		iter = save;
	}
	tree->root = NULL;
}

R_API void r_crbtree_free(RRBTree *tree) {
	if (!tree) {
		return;
	}
	r_crbtree_clear (tree);
	free (tree);
}

R_API RRBNode *r_crbtree_find_node(RRBTree *tree, void *data, RRBComparator cmp, void *user) {
	r_return_val_if_fail (tree && cmp, NULL);

	RRBNode *iter = tree->root;
	while (iter) {
		const int dir = cmp (data, iter->data, user);
		if (!dir) {
			return iter;
		}
		iter = iter->link[dir > 0];
	}
	return NULL;
}

R_API void *r_crbtree_find(RRBTree *tree, void *data, RRBComparator cmp, void *user) {
	r_return_val_if_fail (tree && cmp, NULL);
	RRBNode *node = r_crbtree_find_node (tree, data, cmp, user);
	return node ? node->data : NULL;
}

static RRBNode *_node_new(void *data, RRBNode *parent) {
	RRBNode *node = R_NEW0 (RRBNode);
	r_return_val_if_fail (node, NULL);

	node->red = 1;
	node->data = data;
	node->parent = parent;

	return node;
}

#define IS_RED(n) ((n) && (n)->red == 1)

static RRBNode *_rot_once(RRBNode *root, int dir) {
	r_return_val_if_fail (root, NULL);

	// save is new parent of root and root is parent of save's previous child
	RRBNode *save = root->link[!dir];
	_set_link (root, save->link[dir], !dir);
	_set_link (save, root, dir);

	root->red = 1;
	save->red = 0;

	return save;
}

static RRBNode *_rot_twice(RRBNode *root, int dir) {
	r_return_val_if_fail (root, NULL);

	_set_link (root, _rot_once (root->link[!dir], !dir), !dir);
	return _rot_once (root, dir);
}

R_API bool r_crbtree_insert(RRBTree *tree, void *data, RRBComparator cmp, void *user) {
	r_return_val_if_fail (tree && data && cmp, false);
	bool inserted = false;

	if (!tree->root) {
		tree->root = _node_new (data, NULL);
		if (!tree->root) {
			return false;
		}
		inserted = true;
		goto out_exit;
	}

	RRBNode head; /* Fake tree root */
	memset (&head, 0, sizeof (RRBNode));
	RRBNode *g = NULL, *parent = &head; /* Grandparent & parent */
	RRBNode *p = NULL, *q = tree->root; /* Iterator & parent */
	int dir = 0, last = 0; /* Directions */

	_set_link (parent, q, 1);

	for (;;) {
		if (!q) {
			/* Insert a node at first null link(also set its parent link) */
			q = _node_new (data, p);
			if (!q) {
				return false;
			}
			p->link[dir] = q;
			inserted = true;
		} else if (IS_RED (q->link[0]) && IS_RED (q->link[1])) {
			/* Simple red violation: color flip */
			q->red = 1;
			q->link[0]->red = 0;
			q->link[1]->red = 0;
		}

		if (IS_RED (q) && IS_RED (p)) {
#if 0
			// coverity error, parent is never null
			/* Hard red violation: rotate */
			if (!parent) {
				return false;
			}
#endif
			int dir2 = parent->link[1] == g;
			if (q == p->link[last]) {
				_set_link (parent, _rot_once (g, !last), dir2);
			} else {
				_set_link (parent, _rot_twice (g, !last), dir2);
			}
		}

		if (inserted) {
			break;
		}

		last = dir;
		dir = cmp (data, q->data, user) >= 0;

		if (g) {
			parent = g;
		}

		g = p;
		p = q;
		q = q->link[dir];
	}

	/* Update root(it may different due to root rotation) */
	tree->root = head.link[1];

out_exit:
	/* Invariant: root is black */
	tree->root->red = 0;
	tree->root->parent = NULL;
	if (inserted) {
		tree->size++;
	}

	return inserted;
}

static void _exchange_nodes(RRBNode *node_a, RRBNode *node_b) {
	if (!node_a || !node_b) {
		return;
	}
	RRBNode node_a_tmp, node_b_tmp;
	memcpy (&node_a_tmp, node_a, sizeof (RRBNode));
	memcpy (&node_b_tmp, node_b, sizeof (RRBNode));
	node_a->link[0] = node_b_tmp.link[0];
	node_a->link[1] = node_b_tmp.link[1];
	node_a->red = node_b_tmp.red;
	node_b->link[0] = node_a_tmp.link[0];
	node_b->link[1] = node_a_tmp.link[1];
	node_b->red = node_a_tmp.red;
	if (node_a->parent == node_b->parent) {
		if (node_a->parent) {
			if (node_a->parent->link[0] == node_a) {
				node_a->parent->link[0] = node_b;
				node_a->parent->link[1] = node_a;
			} else {
				node_a->parent->link[1] = node_b;
				node_a->parent->link[0] = node_a;
			}
		}
		if (node_a->link[0]) {
			node_a->link[0]->parent = node_a;
		}
		if (node_a->link[1]) {
			node_a->link[1]->parent = node_a;
		}
		if (node_b->link[0]) {
			node_b->link[0]->parent = node_b;
		}
		if (node_b->link[1]) {
			node_b->link[1]->parent = node_b;
		}
		return;
	}
	RRBNode *parent_a = node_a->parent;
	RRBNode *parent_b = node_b->parent;
	if (parent_a) {
		if (parent_a->link[0] == node_a) {
			parent_a->link[0] = node_b;
		} else {
			parent_a->link[1] = node_b;
		}
	}
	node_b->parent = parent_a;
	if (parent_b) {
		if (parent_b->link[0] == node_b) {
			parent_b->link[0] = node_a;
		} else {
			parent_b->link[1] = node_a;
		}
	}
	node_a->parent = parent_b;
	if (node_a->link[0]) {
		node_a->link[0]->parent = node_a;
	}
	if (node_a->link[1]) {
		node_a->link[1]->parent = node_a;
	}
	if (node_b->link[0]) {
		node_b->link[0]->parent = node_b;
	}
	if (node_b->link[1]) {
		node_b->link[1]->parent = node_b;
	}
}

// remove data from the tree, without freeing it
R_API void *r_crbtree_take(RRBTree *tree, void *data, RRBComparator cmp, void *user) {
	r_return_val_if_fail (tree && data && cmp, NULL);
	if (!tree->root || !tree->size) {
		return NULL;
	}

	RRBNode head; /* Fake tree root */
	memset (&head, 0, sizeof (RRBNode));
	RRBNode *q = &head, *p = NULL, *g = NULL;
	RRBNode *found = NULL;
	int dir = 1, last;

	_set_link (q, tree->root, 1);

	/* Find in-order predecessor */
	while (q->link[dir]) {
		last = dir;

		g = p;
		p = q;
		q = q->link[dir];

		dir = cmp (data, q->data, user);
		if (dir == 0 && !found) {
			found = q;
		}

		dir = (bool)(dir > 0);

		if (IS_RED (q) || IS_RED (q->link[dir])) {
			continue;
		}
		if (IS_RED (q->link[!dir])) {
			_set_link (p, _rot_once (q, dir), last);
			p = p->link[last];
		} else {
			RRBNode *sibling = p->link[!last];
			if (sibling) {
				if (!IS_RED (sibling->link[!last]) && !IS_RED (sibling->link[last])) {
					/* Color flip */
					p->red = 0;
					sibling->red = 1;
					q->red = 1;
				} else if (g) {
					int dir2 = (bool)(g->link[1] == p);

					if (IS_RED (sibling->link[last])) {
						_set_link (g, _rot_twice (p, last), dir2);
					} else {
						_set_link (g, _rot_once (p, last), dir2);
					}

					/* Ensure correct coloring */
					q->red = g->link[dir2]->red = 1;
					g->link[dir2]->link[0]->red = 0;
					g->link[dir2]->link[1]->red = 0;
				}
			}
		}
	}

	void *ret = NULL;
	/* Replace and remove if found */
	if (found) {
		_set_link (p, q->link[q->link[0] == NULL], p->link[1] == q);
		if (q != found) {
			q->link[0] = NULL;
			q->link[1] = NULL;
			q->parent = NULL;
			_exchange_nodes (found, q);
		}
		ret = found->data;
		free (found);
		tree->size--;
	}

	/* Update root node */
	tree->root = head.link[1];
	if (tree->root) {
		tree->root->red = 0;
		tree->root->parent = NULL;
	} else {
		r_return_val_if_fail (tree->size == 0, NULL);
	}
	return ret;
}

R_API bool r_crbtree_delete(RRBTree *tree, void *data, RRBComparator cmp, void *user) {
	r_return_val_if_fail (tree && data && cmp, false);
	if (!(tree->size && tree->root)) {
		return false;
	}
	data = r_crbtree_take (tree, data, cmp, user);
	if (tree->free) {
		tree->free (data);
	}
	return !!data;
}

R_API RRBNode *r_crbtree_first_node(RRBTree *tree) {
	r_return_val_if_fail (tree, NULL);
	if (!tree->root) {
		// empty tree
		return NULL;
	}
	RRBNode *node = tree->root;
	while (node->link[0]) {
		node = node->link[0];
	}
	return node;
}

R_API RRBNode *r_crbtree_last_node(RRBTree *tree) {
	r_return_val_if_fail (tree, NULL);
	if (!tree->root) {
		// empty tree
		return NULL;
	}
	RRBNode *node = tree->root;
	while (node->link[1]) {
		node = node->link[1];
	}
	return node;
}

R_API RRBNode *r_rbnode_next(RRBNode *node) {
	r_return_val_if_fail (node, NULL);
	if (node->link[1]) {
		node = node->link[1];
		while (node->link[0]) {
			node = node->link[0];
		}
		return node;
	}
	RRBNode *parent = node->parent;
	while (parent && parent->link[1] == node) {
		node = parent;
		parent = node->parent;
	}
	return parent;
}

R_API RRBNode *r_rbnode_prev(RRBNode *node) {
	r_return_val_if_fail (node, NULL);
	if (node->link[0]) {
		node = node->link[0];
		while (node->link[1]) {
			node = node->link[1];
		}
		return node;
	}
	RRBNode *parent = node->parent;
	while (parent && parent->link[0] == node) {
		node = parent;
		parent = node->parent;
	}
	return parent;
}
