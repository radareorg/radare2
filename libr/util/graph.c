/* radare - LGPL - Copyright 2007-2024 - pancake, ret2libc, condret */

#include <r_util.h>

R_VEC_TYPE (RVecGraphEdge, RGraphEdge);

enum {
	WHITE_COLOR = 0,
	GRAY_COLOR,
	BLACK_COLOR
};

static RGraphNode *r_graph_node_new(void *data) {
	RGraphNode *p = R_NEW0 (RGraphNode);
	if (p) {
		p->data = data;
// R_NEW0 already sets p->free to NULL
//		p->free = NULL;
		RVecGraphNodePtr_init (&p->out_nodes);
		RVecGraphNodePtr_init (&p->in_nodes);
		RVecGraphNodePtr_init (&p->all_neighbours);
	}
	return p;
}

static void r_graph_node_free(RGraphNode *n) {
	if (!n) {
		return;
	}
	if (n->free) {
		n->free (n->data);
	}
	RVecGraphNodePtr_fini (&n->out_nodes);
	RVecGraphNodePtr_fini (&n->in_nodes);
	RVecGraphNodePtr_fini (&n->all_neighbours);
	free (n);
}

static int node_cmp(unsigned int idx, RGraphNode *b) {
	return idx == b->idx ? 0 : -1;
}

static bool graph_edge_push(RVecGraphEdge *stack, RGraphNode *from, RGraphNode *to, st32 nth) {
	RGraphEdge *edge = RVecGraphEdge_emplace_back (stack);
	edge->from = from;
	edge->to = to;
	edge->nth = nth;
	return true;
}

static int graph_node_ptr_cmp(RGraphNode *const *a, RGraphNode *const *b) {
	return ((*a)->idx > (*b)->idx) - ((*a)->idx < (*b)->idx);
}

static int graph_node_ptr_find_cmp(RGraphNode *const *a, const void *b) {
	const RGraphNode *node = b;
	return ((*a)->idx > node->idx) - ((*a)->idx < node->idx);
}

static void graph_node_vec_insert_sorted(RVecGraphNodePtr *vec, RGraphNode *node) {
	size_t index = RVecGraphNodePtr_lower_bound (vec, &node, graph_node_ptr_cmp);
	RGraphNode **slot = RVecGraphNodePtr_emplace_back (vec);
	RGraphNode **dst = R_VEC_START_ITER (vec) + index;
	memmove (dst + 1, dst, (slot - dst) * sizeof (RGraphNode *));
	*dst = node;
}

static bool graph_node_vec_delete_sorted(RVecGraphNodePtr *vec, const RGraphNode *node) {
	size_t index = RVecGraphNodePtr_find_sorted_index (vec, (void *)node, graph_node_ptr_find_cmp);
	if (index == SZT_MAX) {
		return false;
	}
	RVecGraphNodePtr_remove (vec, index);
	return true;
}

static bool graph_node_vec_delete(RVecGraphNodePtr *vec, const RGraphNode *node) {
	size_t i;
	for (i = 0; i < RVecGraphNodePtr_length (vec); i++) {
		if (*RVecGraphNodePtr_at (vec, i) == node) {
			RVecGraphNodePtr_remove (vec, i);
			return true;
		}
	}
	return false;
}

static void graph_node_vec_insert(RVecGraphNodePtr *vec, RGraphNode *node, int nth) {
	if (nth < 0 || nth >= RVecGraphNodePtr_length (vec)) {
		RVecGraphNodePtr_push_back (vec, &node);
		return;
	}
	RGraphNode **slot = RVecGraphNodePtr_emplace_back (vec);
	RGraphNode **dst = R_VEC_START_ITER (vec) + nth;
	memmove (dst + 1, dst, (slot - dst) * sizeof (RGraphNode *));
	*dst = node;
}

// direction == true => forwards
static void dfs_node(RGraph *g, RGraphNode *n, RGraphVisitor *vis, int color[], const bool direction) {
	if (!n) {
		return;
	}
	RVecGraphEdge s;
	RVecGraphEdge_init (&s);
	RVecGraphEdge_reserve (&s, 2 * g->n_edges + 1);
	if (!graph_edge_push (&s, NULL, n, -1)) {
		RVecGraphEdge_fini (&s);
		return;
	}
	while (!RVecGraphEdge_empty (&s)) {
		RGraphEdge cur_edge = *RVecGraphEdge_last (&s);
		RVecGraphEdge_pop_back (&s);
		RGraphNode **v, *cur = cur_edge.to, *from = cur_edge.from;
		int i;

		if (from && cur) {
			if (color[cur->idx] == WHITE_COLOR && vis->tree_edge) {
				vis->tree_edge (&cur_edge, vis);
			} else if (color[cur->idx] == GRAY_COLOR && vis->back_edge) {
				vis->back_edge (&cur_edge, vis);
			} else if (color[cur->idx] == BLACK_COLOR && vis->fcross_edge) {
				vis->fcross_edge (&cur_edge, vis);
			}
		} else if (!cur && from) {
			if (color[from->idx] != BLACK_COLOR && vis->finish_node) {
				vis->finish_node (from, vis);
			}
			color[from->idx] = BLACK_COLOR;
		}
		if (!cur || color[cur->idx] != WHITE_COLOR) {
			continue;
		}
		if (color[cur->idx] == WHITE_COLOR && vis->discover_node) {
			vis->discover_node (cur, vis);
		}
		color[cur->idx] = GRAY_COLOR;

		if (!graph_edge_push (&s, cur, NULL, -1)) {
			break;
		}

		i = 0;
		const RVecGraphNodePtr *neighbours = direction ? &cur->out_nodes : &cur->in_nodes;
		R_VEC_FOREACH (neighbours, v) {
			if (!graph_edge_push (&s, cur, *v, i++)) {
				break;
			}
		}
	}
	RVecGraphEdge_fini (&s);
}

R_API RGraph *r_graph_new(void) {
	RGraph *t = R_NEW0 (RGraph);
	t->nodes = r_list_new ();
	t->nodes->free = (RListFree)r_graph_node_free;
	t->n_nodes = 0;
	t->last_index = 0;
	return t;
}

R_API void r_graph_free(RGraph* t) {
	if (!t) {
		return;
	}
	r_list_free (t->nodes);
	free (t);
}

R_API RGraphNode *r_graph_get_node(const RGraph *t, unsigned int idx) {
	RListIter *it = r_list_find (t->nodes, (void *)(size_t)idx, (RListComparator)node_cmp);
	if (!it) {
		return NULL;
	}
	return (RGraphNode *)it->data;
}

R_API RListIter *r_graph_node_iter(const RGraph *t, unsigned int idx) {
	return r_list_find (t->nodes, (void *)(size_t)idx, (RListComparator)node_cmp);
}

R_API void r_graph_reset(RGraph *t) {
	r_list_free (t->nodes);
	t->nodes = r_list_new ();
	t->nodes->free = (RListFree)r_graph_node_free;
	t->n_nodes = 0; // XXX isnt r_list_length enough?
	t->n_edges = 0;
	t->last_index = 0;
}

R_API RGraphNode *r_graph_add_node(RGraph *t, void *data) {
	R_RETURN_VAL_IF_FAIL (t && data, NULL);
	RGraphNode *n = r_graph_node_new (data);
	if (n) {
		n->idx = t->last_index++;
		r_list_append (t->nodes, n);
		t->n_nodes++; /// istn r_list_length enough?
	}
	return n;
}

R_API RGraphNode *r_graph_add_nodef(RGraph *graph, void *data, RListFree user_free) {
	RGraphNode *node = r_graph_add_node (graph, data);
	if (node) {
		node->free = user_free;
	}
	return node;
}

/* remove the node from the graph and free the node */
/* users of this function should be aware they can't access n anymore */
R_API void r_graph_del_node(RGraph *t, RGraphNode *n) {
	RGraphNode *gn;
	if (!n) {
		return;
	}
	RGraphNode **it;
	R_VEC_FOREACH (&n->in_nodes, it) {
		gn = *it;
		graph_node_vec_delete (&gn->out_nodes, n);
		graph_node_vec_delete_sorted (&gn->all_neighbours, n);
		t->n_edges--;
	}

	R_VEC_FOREACH (&n->out_nodes, it) {
		gn = *it;
		graph_node_vec_delete_sorted (&gn->in_nodes, n);
		graph_node_vec_delete_sorted (&gn->all_neighbours, n);
		t->n_edges--;
	}

	r_list_delete_data (t->nodes, n);
	t->n_nodes--;
}

R_API void r_graph_add_edge(RGraph *t, RGraphNode *from, RGraphNode *to) {
	r_graph_add_edge_at (t, from, to, -1);
}

R_API void r_graph_add_edge_at(RGraph *t, RGraphNode *from, RGraphNode *to, int nth) {
	if (from && to) {
		graph_node_vec_insert (&from->out_nodes, to, nth);
		graph_node_vec_insert_sorted (&from->all_neighbours, to);
		graph_node_vec_insert_sorted (&to->in_nodes, from);
		graph_node_vec_insert_sorted (&to->all_neighbours, from);
		t->n_edges++;
	}
}

// splits the "split_me", so that new node has it's outnodes
R_API RGraphNode *r_graph_node_split_forward(RGraph *g, RGraphNode *split_me, void *data) {
	RGraphNode *front = r_graph_add_node(g, data);
	RVecGraphNodePtr tmp = front->out_nodes;
	front->out_nodes = split_me->out_nodes;
	split_me->out_nodes = tmp;
	RGraphNode **it;
	R_VEC_FOREACH (&front->out_nodes, it) {
		RGraphNode *n = *it;
		graph_node_vec_delete_sorted (&n->in_nodes, split_me); // optimize me
		graph_node_vec_delete_sorted (&n->all_neighbours, split_me); // boy this all_neighbours is so retarding perf here
		graph_node_vec_delete_sorted (&split_me->all_neighbours, n);
		graph_node_vec_insert_sorted (&n->all_neighbours, front);
		graph_node_vec_insert_sorted (&n->in_nodes, front);
		graph_node_vec_insert_sorted (&front->all_neighbours, n);
	}
	return front;
}

R_API void r_graph_del_edge(RGraph *t, RGraphNode *from, RGraphNode *to) {
	if (!from || !to || !r_graph_adjacent (t, from, to)) {
		return;
	}
	graph_node_vec_delete (&from->out_nodes, to);
	graph_node_vec_delete_sorted (&from->all_neighbours, to);
	graph_node_vec_delete_sorted (&to->in_nodes, from);
	graph_node_vec_delete_sorted (&to->all_neighbours, from);
	t->n_edges--;
}

// XXX remove comments and static inline all this crap
/* returns the list of nodes reachable from `n` */
R_API const RVecGraphNodePtr *r_graph_get_neighbours(const RGraph *g, const RGraphNode *n) {
	return n? &n->out_nodes: NULL;
}

/* returns the n-th nodes reachable from the give node `n`.
 * This, of course, depends on the order of the nodes. */
R_API RGraphNode *r_graph_nth_neighbour(const RGraph *g, const RGraphNode *n, int nth) {
	RGraphNode **node = n? RVecGraphNodePtr_at (&n->out_nodes, nth): NULL;
	return node? *node: NULL;
}

/* returns the list of nodes that can reach `n` */
R_API const RVecGraphNodePtr *r_graph_innodes(const RGraph *g, const RGraphNode *n) {
	return n? &n->in_nodes: NULL;
}

/* returns the list of nodes reachable from `n` and that can reach `n`. */
R_API const RVecGraphNodePtr *r_graph_all_neighbours(const RGraph *g, const RGraphNode *n) {
	return n? &n->all_neighbours: NULL;
}

R_API const RList *r_graph_get_nodes(const RGraph *g) {
	return g? g->nodes: NULL;
}

/* true if there is an edge from the node `from` to the node `to` */
R_API bool r_graph_adjacent(const RGraph *g, const RGraphNode *from, const RGraphNode *to) {
	if (!g || !from) {
		return false;
	}
	return RVecGraphNodePtr_find (&from->out_nodes, (void *)to, graph_node_ptr_find_cmp) != NULL;
}

R_API void r_graph_dfs_node(RGraph *g, RGraphNode *n, RGraphVisitor *vis) {
	if (!g || !n || !vis) {
		return;
	}
	int *color = R_NEWS0 (int, g->last_index);
	if (color) {
		dfs_node (g, n, vis, color, true);
		free (color);
	}
}

R_API void r_graph_dfs_node_reverse(RGraph *g, RGraphNode *n, RGraphVisitor *vis) {
	if (!g || !n || !vis) {
		return;
	}
	int *color = R_NEWS0 (int, g->last_index);
	if (color) {
		dfs_node (g, n, vis, color, false);
		free (color);
	}
}

R_API void r_graph_dfs(RGraph *g, RGraphVisitor *vis) {
	R_RETURN_IF_FAIL (g && vis);
	RGraphNode *n;
	RListIter *it;

	int *color = R_NEWS0 (int, g->last_index);
	if (color) {
		r_list_foreach (g->nodes, it, n) {
			if (color[n->idx] == WHITE_COLOR) {
				dfs_node (g, n, vis, color, true);
			}
		}
		free (color);
	}
}

static void _postorder_collect(RGraphNode *n, RGraphVisitor *vis) {
	RVecGraphNodePtr_push_back ((RVecGraphNodePtr *)vis->data, &n);
}

static size_t dom_intersect(const size_t *idom, size_t f1, size_t f2) {
	while (f1 != f2) {
		while (f1 < f2) {
			f1 = idom[f1];
		}
		while (f2 < f1) {
			f2 = idom[f2];
		}
	}
	return f1;
}

// Cooper-Harvey-Kennedy iterative dominators; tree node data points at the input graph nodes
R_API RGraph *r_graph_dom_tree(RGraph *graph, RGraphNode *root) {
	R_RETURN_VAL_IF_FAIL (graph && root, NULL);
	RVecGraphNodePtr order;
	RVecGraphNodePtr_init (&order);
	RGraphVisitor vis = { .finish_node = _postorder_collect, .data = &order };
	r_graph_dfs_node (graph, root, &vis);
	const size_t n = RVecGraphNodePtr_length (&order);
	// pon[node->idx] is the postorder number plus one; 0 marks unreachable nodes
	size_t *pon = R_NEWS0 (size_t, graph->last_index);
	size_t *idom = R_NEWS (size_t, n);
	RGraphNode **tnodes = R_NEWS0 (RGraphNode *, n);
	RGraph *g = r_graph_new ();
	if (!n || !pon || !idom || !tnodes) {
		r_graph_free (g);
		g = NULL;
		goto beach;
	}
	size_t i;
	for (i = 0; i < n; i++) {
		pon[(*RVecGraphNodePtr_at (&order, i))->idx] = i + 1;
		idom[i] = SZT_MAX;
	}
	// the root finishes last, so it takes the highest postorder number
	idom[n - 1] = n - 1;
	bool changed = true;
	while (changed) {
		changed = false;
		for (i = n - 1; i-- > 0;) {
			RGraphNode *b = *RVecGraphNodePtr_at (&order, i);
			size_t nid = SZT_MAX;
			RGraphNode **it;
			R_VEC_FOREACH (&b->in_nodes, it) {
				size_t p = pon[(*it)->idx];
				if (!p || idom[p - 1] == SZT_MAX) {
					continue;
				}
				p--;
				nid = (nid == SZT_MAX)? p: dom_intersect (idom, p, nid);
			}
			if (nid != SZT_MAX && idom[i] != nid) {
				idom[i] = nid;
				changed = true;
			}
		}
	}
	for (i = n; i-- > 0;) {
		tnodes[i] = r_graph_add_node (g, *RVecGraphNodePtr_at (&order, i));
	}
	for (i = n - 1; i-- > 0;) {
		r_graph_add_edge (g, tnodes[idom[i]], tnodes[i]);
	}
beach:
	free (pon);
	free (idom);
	free (tnodes);
	RVecGraphNodePtr_fini (&order);
	return g;
}

static void _invert_edges (RGraph *g) {
	RListIter *iter;
	RGraphNode *n;
	r_list_foreach (g->nodes, iter, n) {
		RVecGraphNodePtr tmp = n->in_nodes;
		n->in_nodes = n->out_nodes;
		n->out_nodes = tmp;
	}
}

R_API RGraph *r_graph_pdom_tree(RGraph *graph, RGraphNode *root) {
	R_RETURN_VAL_IF_FAIL (graph && root, NULL);
	_invert_edges (graph);
	RGraph *g = r_graph_dom_tree (graph, root);
	_invert_edges (graph);
	return g;
}
