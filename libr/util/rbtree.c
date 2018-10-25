/* radare - BSD 3 Clause License - Copyright 2017 - MaskRay */

#include <stdio.h>

#include "r_util/r_rbtree.h"

static inline bool red(RBNode *x) {
	return x && x->red;
}

static inline RBNode *zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = x->child[dir];
	x->child[dir] = y->child[!dir];
	y->child[!dir] = x;
	x->red = true;
	y->red = false;
	if (sum) {
		sum (x);
	}
	return y;
}

static inline RBNode *zig_zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = x->child[dir], *z = y->child[!dir];
	y->child[!dir] = z->child[dir];
	z->child[dir] = y;
	x->child[dir] = z->child[!dir];
	z->child[!dir] = x;
	x->red = y->red = true;
	z->red = false;
	if (sum) {
		sum (x);
		sum (y);
	}
	return z;
}

static inline RBIter bound_iter(RBNode *x, void *data, RBComparator cmp, bool upper, bool backward) {
	RBIter it;
	it.len = 0;
	while (x) {
		int d = cmp (data, x);
		if (upper ? d < 0 : d <= 0) {
			if (!backward) {
				it.path[it.len++] = x;
			}
			x = x->child[0];
		} else {
			if (backward) {
				it.path[it.len++] = x;
			}
			x = x->child[1];
		}
	}
	return it;
}

/*
static void _check1(RBNode *x, int dep, int black, bool leftmost) {
	static int black_;
	if (x) {
		black += !x->red;
		if (x->red && ((x->child[0] && x->child[0]->red) || (x->child[1] && x->child[1]->red))) {
			printf ("error: red violation\n");
		}
		_check1 (x->child[0], dep + 1, black, leftmost);
		_check1 (x->child[1], dep + 1, black, false);
	} else if (leftmost) {
		black_ = black;
	} else if (black_ != black) {
		printf ("error: different black height\n");
	}
}

static void _check(RBNode *x) {
	_check1 (x, 0, 0, true);
}
*/

// Returns true if a node with an equal key is deleted
R_API bool r_rbtree_aug_delete(RBNode **root, void *data, RBComparator cmp, RBNodeFree freefn, RBNodeSum sum) {
	RBNode head, *del = NULL, **del_link = NULL, *g = NULL, *p = NULL, *q = &head, *path[R_RBTREE_MAX_HEIGHT];
	int d = 1, d2, dep = 0;
	head.child[0] = NULL;
	head.child[1] = *root;
	while (q->child[d]) {
		d2 = d;
		g = p;
		p = q;
		if (del_link) {
			d = 1;
		} else {
			d = cmp (data, q->child[d2]);
			if (d < 0) {
				d = 0;
			} else if (d > 0) {
				d = 1;
			} else {
				del_link = &q->child[d2];
			}
		}
		if (q != &head) {
			if (dep >= R_RBTREE_MAX_HEIGHT) {
				eprintf ("Too deep tree\n");
				break;
			}
			path[dep++] = q;
		}
		q = q->child[d2];
		if (q->red || red (q->child[d])) {
			continue;
		}
		if (red (q->child[!d])) {
			if (del_link && *del_link == q) {
				del_link = &q->child[!d]->child[d];
			}
			p->child[d2] = zag (q, !d, sum);
			p = p->child[d2];
			if (dep >= R_RBTREE_MAX_HEIGHT) {
				eprintf ("Too deep tree\n");
				break;
			}
			path[dep++] = p;
		} else {
			RBNode *s = p->child[!d2];
			if (! s) {
				continue;
			}
			if (! red (s->child[0]) && ! red (s->child[1])) {
				p->red = false;
				q->red = s->red = true;
			} else {
				int d3 = g->child[0] != p;
				RBNode *t;
				if (red (s->child[d2])) {
					if (del_link && *del_link == p) {
						del_link = &s->child[d2]->child[d2];
					}
					t = zig_zag (p, !d2, sum);
				} else {
					if (del_link && *del_link == p) {
						del_link = &s->child[d2];
					}
					t = zag (p, !d2, sum);
				}
				t->red = q->red = true;
				t->child[0]->red = t->child[1]->red = false;
				g->child[d3] = t;
				path[dep - 1] = t;
				path[dep++] = p;
			}
		}
	}
	if (del_link) {
		del = *del_link;
		p->child[q != p->child[0]] = q->child[q->child[0] == NULL];
		if (del != q) {
			*q = *del;
			*del_link = q;
		}
		if (freefn) {
			freefn (del);
		}
	}
	if (sum) {
		while (dep--) {
			sum (path[dep] == del ? q : path[dep]);
		}
	}
	if ((*root = head.child[1])) {
		(*root)->red = false;
	}
	return del;
}

// Returns 1 if `data` is inserted; 0 if an equal key already exists; -1 if allocation fails.
R_API void r_rbtree_aug_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, RBNodeSum sum) {
	node->child[0] = node->child[1] = NULL;
	if (!*root) {
		*root = node;
		node->red = false;
		if (sum) {
			sum (node);
		}
		return;
	}
	RBNode *t = NULL, *g = NULL, *p = NULL, *q = *root;
	int d, dep = 0;
	bool done = false;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
	for (;;) {
		if (!q) {
			q = node;
			q->red = true;
			p->child[d] = q;
			done = true;
		} else if (red (q->child[0]) && red (q->child[1])) {
			q->child[0]->red = q->child[1]->red = false;
			if (q != *root) {
				q->red = true;
			}
		}
		if (q->red && p && p->red) {
			int d3 = t ? t->child[0] != g : -1, d2 = g->child[0] != p;
			if (p->child[d2] == q) {
				g = zag (g, d2, sum);
				dep--;
				path[dep - 1] = g;
			} else {
				g = zig_zag (g, d2, sum);
				dep -= 2;
			}
			if (t) {
				t->child[d3] = g;
			} else {
				*root = g;
			}
		}
		if (done) {
			break;
		}
		d = cmp (data, q);
		t = g;
		g = p;
		p = q;
		if (dep >= R_RBTREE_MAX_HEIGHT) {
			eprintf ("Too deep tree\n");
			break;
		}
		path[dep++] = q;
		if (d < 0) {
			d = 0;
			q = q->child[0];
		} else {
			d = 1;
			q = q->child[1];
		}
	}
	if (sum) {
		sum (q);
		while (dep) {
			sum (path[--dep]);
		}
	}
}

// returns true if the sum has been updated, false if node has not been found
R_API bool r_rbtree_aug_update_sum(RBNode *root, void *data, RBNode *node, RBComparator cmp, RBNodeSum sum) {
	int dep = 0;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
	RBNode *cur = root;
	for (;;) {
		if (dep >= R_RBTREE_MAX_HEIGHT) {
			eprintf ("Too deep tree\n");
			return false;
		}
		if (!cur) {
			return false;
		}
		path[dep] = cur;
		dep++;
		if (cur == node) {
			break;
		}

		int d = cmp (data, cur);
		if (d < 0) {
			cur = cur->child[0];
		} else {
			cur = cur->child[1];
		}
	}

	for(; dep > 0; dep--) {
		sum (path[dep-1]);
	}
	return true;
}

R_API bool r_rbtree_delete(RBNode **root, void *data, RBComparator cmp, RBNodeFree freefn) {
	return r_rbtree_aug_delete (root, data, cmp, freefn, NULL);
}

R_API RBNode *r_rbtree_find(RBNode *x, void *data, RBComparator cmp) {
	while (x) {
		int d = cmp (data, x);
		if (d < 0) {
			x = x->child[0];
		} else if (d > 0) {
			x = x->child[1];
		} else {
			return x;
		}
	}
	return NULL;
}

R_API void r_rbtree_free(RBNode *x, RBNodeFree freefn) {
	if (x) {
		r_rbtree_free (x->child[0], freefn);
		r_rbtree_free (x->child[1], freefn);
		freefn (x);
	}
}

R_API void r_rbtree_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp) {
	r_rbtree_aug_insert (root, data, node, cmp, NULL);
}

R_API RBNode *r_rbtree_lower_bound(RBNode *x, void *data, RBComparator cmp) {
	RBNode *ret = NULL;
	while (x) {
		int d = cmp (data, x);
		if (d <= 0) {
			ret = x;
			x = x->child[0];
		} else {
			x = x->child[1];
		}
	}
	return ret;
}

R_API RBIter r_rbtree_lower_bound_backward(RBNode *root, void *data, RBComparator cmp) {
	return bound_iter (root, data, cmp, false, true);
}

R_API RBIter r_rbtree_lower_bound_forward(RBNode *root, void *data, RBComparator cmp) {
	return bound_iter (root, data, cmp, false, false);
}

R_API RBNode *r_rbtree_upper_bound(RBNode *x, void *data, RBComparator cmp) {
	void *ret = NULL;
	while (x) {
		int d = cmp (data, x);
		if (d < 0) {
			ret = x;
			x = x->child[0];
		} else {
			x = x->child[1];
		}
	}
	return ret;
}

R_API RBIter r_rbtree_upper_bound_backward(RBNode *root, void *data, RBComparator cmp) {
	return bound_iter (root, data, cmp, true, true);
}

R_API RBIter r_rbtree_upper_bound_forward(RBNode *root, void *data, RBComparator cmp) {
	return bound_iter (root, data, cmp, true, false);
}

static RBIter _first(RBNode *x, int dir) {
	RBIter it;
	it.len = 0;
	for (; x; x = x->child[dir]) {
		it.path[it.len++] = x;
	}
	return it;
}

R_API RBIter r_rbtree_first(RBNode *tree) {
	return _first (tree, 0);
}

R_API RBIter r_rbtree_last(RBNode *tree) {
	return _first (tree, 1);
}

static inline void _next(RBIter *it, int dir) {
	RBNode *x = it->path[--it->len];
	for (x = x->child[!dir]; x; x = x->child[dir]) {
		it->path[it->len++] = x;
	}
}

R_API void r_rbtree_iter_next(RBIter *it) {
	_next (it, 0);
}

R_API void r_rbtree_iter_prev(RBIter *it) {
	_next (it, 1);
}
