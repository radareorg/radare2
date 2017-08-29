#include "r_util/r_rbtree.h"

static void rbnode_clear(RListFree freefn, RBNode *x) {
	if (x) {
		rbnode_clear (freefn, x->child[0]);
		rbnode_clear (freefn, x->child[1]);
		if (freefn) {
			freefn (x->data);
		}
		free (x);
	}
}

R_API void r_rbtree_clear(RBTree *tree) {
	rbnode_clear (tree->free, tree->root);
	tree->root = NULL;
	tree->size = 0;
}

static inline bool red(RBNode *x) {
	return x && x->red;
}

static inline RBNode *zag(RBNode *x, int dir) {
	RBNode *y = x->child[dir];
	x->child[dir] = y->child[!dir];
	y->child[!dir] = x;
	x->red = true;
	y->red = false;
	return y;
}

static inline RBNode *zig_zag(RBNode *x, int dir) {
	x->child[dir] = zag (x->child[dir], !dir);
	return zag (x, dir);
}

// Returns true if a node with an equal key is deleted
R_API bool r_rbtree_delete(RBTree *tree, void *data, void *user) {
	RBNode head, *del = NULL, *g = NULL, *p = NULL, *q = &head;
	head.child[0] = NULL;
	head.child[1] = tree->root;
	int d = 1, d2;
	while (q->child[d]) {
		d2 = d;
		g = p;
		p = q;
		q = q->child[d];
		if (del) {
			d = 1;
		} else {
			d = tree->cmp (data, q->data, user);
			if (d < 0) {
				d = 0;
			} else if (d > 0) {
				d = 1;
			} else {
				del = q;
			}
		}
		if (q->red || red (q->child[d])) {
			continue;
		}
		if (red (q->child[!d])) {
			p->child[d2] = zag(q, !d);
			p = p->child[d2];
		} else {
			RBNode *s = p->child[!d2];
			if (! s) {
				continue;
			}
			if (! red (s->child[0]) || ! red (s->child[1])) {
				p->red = false;
				q->red = s->red = true;
			} else {
				int d3 = g->child[0] != p;
				RBNode *t = red (s->child[d2]) ? zig_zag (p, !d2) : zag (p, !d2);
				t->red = q->red = true;
				t->child[0]->red = t->child[1]->red = false;
				g->child[d3] = t;
			}
		}
	}
	if (!del) {
		tree->root = head.child[1];
		if (tree->root) {
			tree->root->red = false;
		}
		return false;
	}
	p->child[q != p->child[0]] = q->child[q->child[0] == NULL];
	if (tree->free) {
		tree->free (del->data);
	}
	del->data = q->data;
	free (q);
	tree->root = head.child[1];
	if (tree->root) {
		tree->root->red = false;
	}
	tree->size--;
	return true;
}

R_API void *r_rbtree_find(RBTree *tree, void *data, void *user) {
	RBNode *x = tree->root;
	while (x) {
		int d = tree->cmp (data, x->data, user);
		if (d < 0) {
			x = x->child[0];
		} else if (d > 0) {
			x = x->child[1];
		} else {
			return x->data;
		}
	}
	return NULL;
}

R_API RBTree *r_rbtree_new(RListFree free, RBTreeComparator cmp) {
	RBTree *ret = R_NEW (RBTree);
	if (!ret) {
		return NULL;
	}
	ret->root = NULL;
	ret->free = free;
	ret->cmp = cmp;
	ret->size = 0;
	return ret;
}

R_API void r_rbtree_free(RBTree *tree) {
	r_rbtree_clear (tree);
	free (tree);
}

// Returns 1 if `data` is inserted; 0 if an equal key already exists; -1 if allocation fails.
R_API int r_rbtree_insert(RBTree *tree, void *data, void *user) {
	if (!tree->root) {
		RBNode *q = R_NEW (RBNode);
		if (!q) {
			return -1;
		}
		q->data = data;
		q->child[0] = q->child[1] = NULL;
		q->red = false;
		tree->root = q;
		return tree->size = 1;
	}
	RBNode *t = NULL, *g = NULL, *p = NULL, *q = tree->root;
	int d;
	bool done = false;
	do {
		if (!q && p) {
			q = R_NEW (RBNode);
			if (!q) {
				return -1;
			}
			q->data = data;
			q->child[0] = q->child[1] = NULL;
			q->red = true;
			p->child[d] = q;
			done = true;
		} else if (red (q->child[0]) && red (q->child[1])) {
			q->child[0]->red = q->child[1]->red = false;
			if (q != tree->root) {
				q->red = true;
			}
		}
		if (q->red && p && p->red) {
			int d3 = t ? t->child[0] != g : -1, d2 = g->child[0] != p;
			g = p->child[d2] == q ? zag (g, d2) : zig_zag (g, d2);
			if (t) {
				t->child[d3] = g;
			} else {
				tree->root = g;
			}
		}
		if (done) {
			break;
		}
		d = tree->cmp (data, q->data, user);
		t = g;
		g = p;
		p = q;
		if (d < 0) {
			d = 0;
			q = q->child[0];
		} else if (d > 0) {
			d = 1;
			q = q->child[1];
		} else {
			return 0;
		}
	} while (!done);
	tree->size++;
	return 1;
}

R_API void *r_rbtree_lower_bound(RBTree *tree, void *data, void *user) {
	void *ret = NULL;
	RBNode *x = tree->root;
	while (x) {
		int d = tree->cmp (data, x->data, user);
		if (d < 0) {
			ret = x->data;
			x = x->child[0];
		} else if (d > 0) {
			x = x->child[1];
		} else {
			return x->data;
		}
	}
	return ret;
}

static inline RBTreeIter bound_iter(RBTree *tree, void *data, void *user, bool upper, bool dir) {
	RBTreeIter it;
	it.len = 0;
	RBNode *x = tree->root;
	while (x) {
		int d = tree->cmp (data, x->data, user);
		if (d < 0) {
			if (!dir) {
				it.path[it.len++] = x;
			}
			x = x->child[0];
		} else if (upper || d > 0) {
			if (dir) {
				it.path[it.len++] = x;
			}
			x = x->child[1];
		} else {
			if (!dir) {
				it.path[it.len++] = x;
			}
			break;
		}
	}
	return it;
}

R_API RBTreeIter r_rbtree_lower_bound_backward(RBTree *tree, void *data, void *user) {
	return bound_iter (tree, data, user, false, true);
}

R_API RBTreeIter r_rbtree_lower_bound_forward(RBTree *tree, void *data, void *user) {
	return bound_iter (tree, data, user, false, false);
}

R_API void *r_rbtree_upper_bound(RBTree *tree, void *data, void *user) {
	void *ret = NULL;
	RBNode *x = tree->root;
	while (x) {
		int d = tree->cmp (data, x->data, user);
		if (d < 0) {
			ret = x->data;
			x = x->child[0];
		} else {
			x = x->child[1];
		}
	}
	return ret;
}

R_API RBTreeIter r_rbtree_upper_bound_backward(RBTree *tree, void *data, void *user) {
	return bound_iter (tree, data, user, true, true);
}

R_API RBTreeIter r_rbtree_upper_bound_forward(RBTree *tree, void *data, void *user) {
	return bound_iter (tree, data, user, true, false);
}

static void print(RBNode *x, int dep, int black, bool leftmost) {
	static int black_;
	if (x) {
		black += !x->red;
		print (x->child[0], dep + 1, black, leftmost);
		printf("%*s%p%s\n", 2 * dep, "", x->data, x->red ? " R" : "");
		print (x->child[1], dep + 1, black, false);
	} else if (leftmost) {
		black_ = black;
	} else if (black_ != black) {
		printf ("error: different black height\n");
	}
}

R_API void r_rbtree_print(RBTree *tree) {
	print (tree->root, 0, 0, true);
}

R_API int r_rbtree_size(RBTree *tree) {
	return tree->size;
}

static RBTreeIter first(RBTree *tree, int dir) {
	RBTreeIter it;
	RBNode *x = tree->root;
	it.len = 0;
	for (; x; x = x->child[dir]) {
		it.path[it.len++] = x;
	}
	return it;
}

R_API RBTreeIter r_rbtree_first(RBTree *tree) {
	return first (tree, 0);
}

R_API RBTreeIter r_rbtree_last(RBTree *tree) {
	return first (tree, 1);
}

static inline void *next(RBTreeIter *it, int dir) {
	RBNode *x = it->path[--it->len];
	void *data = x->data;
	for (x = x->child[!dir]; x; x = x->child[dir]) {
		it->path[it->len++] = x;
	}
	return data;
}

R_API bool r_rbtree_iter_has(RBTreeIter *it) {
	return it->len;
}

R_API void *r_rbtree_iter_next(RBTreeIter *it) {
	return next (it, 0);
}

R_API void *r_rbtree_iter_prev(RBTreeIter *it) {
	return next (it, 1);
}
