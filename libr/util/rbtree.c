/* radare - BSD 3 Clause License - Copyright 2017-2021 - MaskRay, condret */

#include <stdio.h>

#include <r_util/r_rbtree.h>
#include <r_util.h>

static inline bool red(RBNode *x) {
	return x && x->red;
}

static inline RBNode *zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = x->child[dir];
	x->child[dir] = y->child[!dir];
	if (x->child[dir]) {
		x->child[dir]->parent = x;
	}
	y->child[!dir] = x;
	x->parent = y;
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
	if (y->child[!dir]) {
		y->child[!dir]->parent = y;
	}
	z->child[dir] = y;
	y->parent = z;
	x->child[dir] = z->child[!dir];
	if (x->child[dir]) {
		x->child[dir]->parent = x;
	}
	z->child[!dir] = x;
	x->parent = z;
	x->red = y->red = true;
	z->red = false;
	if (sum) {
		sum (x);
		sum (y);
	}
	return z;
}

static inline RBIter bound_iter(RBNode *x, void *data, RBComparator cmp, bool upper, void *user) {
	RBIter it;
	it.len = 0;
	memset (it.path, 0, sizeof (RBNode *) * R_RBTREE_MAX_HEIGHT);
	while (x) {
		int d = cmp (data, x, user);

		if (d == 0) {
			it.path[it.len++] = x;
			return it;
		}

		if (d < 0) {
			if (!upper) {
				it.path[it.len++] = x;
			}
			x = x->child[0];
		} else {
			if (upper) {
				it.path[it.len++] = x;
			}
			x = x->child[1];
		}
	}

	return it;
}

/*
static void _check1(RBNode *x, int depth, int black, bool leftmost) {
	static int black_;
	if (x) {
		black += !x->red;
		if (x->red && ((x->child[0] && x->child[0]->red) || (x->child[1] && x->child[1]->red))) {
			printf ("error: red violation\n");
		}
		_check1 (x->child[0], depth + 1, black, leftmost);
		_check1 (x->child[1], depth + 1, black, false);
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
R_API bool r_rbtree_aug_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user, RBNodeSum sum) {
	RBNode head, *del = NULL, **del_link = NULL, *g = NULL, *p = NULL, *q = &head, *path[R_RBTREE_MAX_HEIGHT];
	int direction = 1, direction2, depth = 0;
	head.parent = head.child[0] = NULL;
	head.child[1] = *root;
	while (q->child[direction]) {
		direction2 = direction;
		g = p;
		p = q;
		if (del_link) {
			direction = 1;
		} else {
			direction = cmp (data, q->child[direction2], cmp_user);
			if (direction < 0) {
				direction = 0;
			} else if (direction > 0) {
				direction = 1;
			} else {
				del_link = &q->child[direction2];
			}
		}
		if (q != &head) {
			if (depth >= R_RBTREE_MAX_HEIGHT) {
				eprintf ("Too deep tree\n");
				break;
			}
			path[depth++] = q;
		}
		q = q->child[direction2];
		if (q->red || red (q->child[direction])) {
			continue;
		}
		if (red (q->child[!direction])) {
			if (del_link && *del_link == q) {
				del_link = &q->child[!direction]->child[direction];
			}
			p->child[direction2] = zag (q, !direction, sum);
			p->child[direction2]->parent = p->parent;
			p = p->child[direction2];	//memleak here?
			if (depth >= R_RBTREE_MAX_HEIGHT) {
				eprintf ("Too deep tree\n");
				break;
			}
			path[depth++] = p;
		} else {
			RBNode *s = p->child[!direction2];
			if (!s) {
				continue;
			}
			if (!red (s->child[0]) && !red (s->child[1])) {
				p->red = false;
				q->red = s->red = true;
			} else {
				int direction3 = g->child[0] != p;
				RBNode *t;
				if (red (s->child[direction2])) {
					if (del_link && *del_link == p) {
						del_link = &s->child[direction2]->child[direction2];
					}
					t = zig_zag (p, !direction2, sum);
				} else {
					if (del_link && *del_link == p) {
						del_link = &s->child[direction2];
					}
					t = zag (p, !direction2, sum);
				}
				t->red = q->red = true;
				t->child[0]->red = t->child[1]->red = false;
				g->child[direction3] = t;
				t->parent = g;
				if (depth >= R_RBTREE_MAX_HEIGHT) {
					eprintf ("Too deep tree\n");
					break;
				}
				path[depth - 1] = t;
				path[depth++] = p;
			}
		}
	}
	if (del_link && *del_link) {
		del = *del_link;
		if (q->child[q->child[0] == NULL]) {
			q->child[q->child[0] == NULL]->parent = p;
		}
		p->child[q != p->child[0]] = q->child[q->child[0] == NULL];
		if (del != q) {
			*q = *del;
			*del_link = q;
		}
		if (freefn) {
			freefn (del, free_user);
		}
	}
	if (sum) {
		if (depth >= R_RBTREE_MAX_HEIGHT) {
			eprintf ("Too deep tree\n");
			depth--;
		}
		while (depth--) {
			sum (path[depth] == del ? q : path[depth]);
		}
	}
	if ((*root = head.child[1])) {
		(*root)->red = false;
		(*root)->parent = NULL;
	}
	return del;
}

// Returns true if stuff got inserted, else false
R_API bool r_rbtree_aug_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum) {
	node->parent = node->child[0] = node->child[1] = NULL;
	if (!*root) {
		*root = node;
		node->red = false;
		if (sum) {
			sum (node);
		}
		return true;
	}
	RBNode *t = NULL, *g = NULL, *p = NULL, *q = *root;
	int direction = 0, depth = 0;
	bool done = false;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
	for (;;) {
		if (!q) {
			q = node;
			q->red = true;
			p->child[direction] = q;
			q->parent = p;
			done = true;
		} else if (red (q->child[0]) && red (q->child[1])) {
			q->child[0]->red = q->child[1]->red = false;
			if (q != *root) {
				q->red = true;
			}
		}
		if (q->red && p && p->red) {
			int direction3 = t ? t->child[0] != g : -1;
			int direction2 = g->child[0] != p;
			if (p->child[direction2] == q) {
				g = zag (g, direction2, sum);
				depth--;
				path[depth - 1] = g;
			} else {
				g = zig_zag (g, direction2, sum);
				depth -= 2;
			}
			if (t) {
				t->child[direction3] = g;
				g->parent = t;
			} else {
				*root = g;
				g->parent = NULL;
			}
		}
		if (done) {
			break;
		}
		direction = cmp (data, q, cmp_user);
		t = g;
		g = p;
		p = q;
		if (depth >= R_RBTREE_MAX_HEIGHT) {
			eprintf ("Too deep tree\n");
			break;
		}
		path[depth++] = q;
		if (direction < 0) {
			direction = 0;
			q = q->child[0];
		} else {
			direction = 1;
			q = q->child[1];
		}
	}
	if (sum) {
		sum (q);
		while (depth) {
			sum (path[--depth]);
		}
	}
	return done;
}

// returns true if the sum has been updated, false if node has not been found
R_API bool r_rbtree_aug_update_sum(RBNode *root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum) {
	size_t depth = 0;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
	RBNode *cur = root;
	for (;;) {
		if (!cur) {
			return false;
		}
		if (depth >= R_RBTREE_MAX_HEIGHT) {
			eprintf ("Too deep tree\n");
			return false;
		}
		path[depth] = cur;
		depth++;
		if (cur == node) {
			break;
		}
		int direction = cmp (data, cur, cmp_user);
		cur = cur->child[(direction < 0)? 0: 1];
	}

	for (; depth > 0; depth--) {
		sum (path[depth - 1]);
	}
	return true;
}

R_API bool r_rbtree_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user) {
	return r_rbtree_aug_delete (root, data, cmp, cmp_user, freefn, free_user, NULL);
}

R_API RBNode *r_rbtree_find(RBNode *x, void *data, RBComparator cmp, void *user) {
	while (x) {
		int direction = cmp (data, x, user);
		if (direction < 0) {
			x = x->child[0];
		} else if (direction > 0) {
			x = x->child[1];
		} else {
			return x;
		}
	}
	return NULL;
}

R_API void r_rbtree_free(RBNode *x, RBNodeFree freefn, void *user) {
	if (x) {
		r_rbtree_free (x->child[0], freefn, user);
		r_rbtree_free (x->child[1], freefn, user);
		freefn (x, user);
	}
}

R_API void r_rbtree_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *user) {
	r_rbtree_aug_insert (root, data, node, cmp, user, NULL);
}

R_API RBNode *r_rbtree_lower_bound(RBNode *x, void *data, RBComparator cmp, void *user) {
	RBNode *ret = NULL;
	while (x) {
		int direction = cmp (data, x, user);
		if (direction <= 0) {
			ret = x;
			x = x->child[0];
		} else {
			x = x->child[1];
		}
	}
	return ret;
}

R_API RBIter r_rbtree_lower_bound_forward(RBNode *root, void *data, RBComparator cmp, void *user) {
	return bound_iter (root, data, cmp, false, user);
}

R_API RBNode *r_rbtree_upper_bound(RBNode *x, void *data, RBComparator cmp, void *user) {
	void *ret = NULL;
	while (x) {
		int direction = cmp (data, x, user);
		if (direction < 0) {
			x = x->child[0];
		} else {
			ret = x;
			x = x->child[1];
		}
	}
	return ret;
}

R_API RBIter r_rbtree_upper_bound_backward(RBNode *root, void *data, RBComparator cmp, void *user) {
	return bound_iter (root, data, cmp, true, user);
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
