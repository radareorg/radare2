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
	if (!edge) {
		return false;
	}
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
	if (!slot) {
		return;
	}
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
	if (!slot) {
		return;
	}
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

typedef struct _dfs_inserter {
	RGraph *g;
	HtUP *reverse;	//reverse lookup of nodes
//	RList *mo;	//multiple out nodes
	RVecGraphNodePtr mi; // multiple in nodes
	size_t mi_index;
	ut32 idx;
	bool fail;
} DfsInserter;

static void _dfs_ins_node(RGraphNode *n, RGraphVisitor *vi) {
	DfsInserter *di = (DfsInserter *)vi->data;
	if (di->fail) {
		return;
	}
	RGraphDomNode *dn = R_NEW0 (RGraphDomNode);
	if (!dn) {
		di->fail = true;
		return;
	}
	RGraphNode *node = r_graph_add_nodef (di->g, dn, free);
	if (!node) {
		free (dn);
		di->fail = true;
		return;
	}
	dn->node = n;
	ht_up_insert (di->reverse, (ut64)(size_t)n, node);
	if (RVecGraphNodePtr_length (&n->in_nodes) > 1 && di->idx) {
		RGraphNode **slot = RVecGraphNodePtr_emplace_back (&di->mi);
		if (!slot) {
			di->fail = true;
			return;
		}
		*slot = node;
	}
	dn->idx = di->idx++;
}

static void _dfs_ins_edge(const RGraphEdge *e, RGraphVisitor *vi) {
	DfsInserter *di = (DfsInserter *)vi->data;
	if (di->fail) {
		return;
	}
	bool found;
	RGraphNode *from = (RGraphNode *)ht_up_find (di->reverse, (ut64)(size_t)e->from, &found);
	if (!found) {
		_dfs_ins_node (e->from, vi);
		if (di->fail) {
			return;
		}
		from = (RGraphNode *)ht_up_find (di->reverse, (ut64)(size_t)e->from, &found);
		if (!found) {
			return;
		}
	}
	RGraphNode *to = (RGraphNode *)ht_up_find (di->reverse, (ut64)(size_t)e->to, &found);
	if (!found) {
		_dfs_ins_node (e->to, vi);
		if (di->fail) {
			return;
		}
		to = (RGraphNode *)ht_up_find (di->reverse, (ut64)(size_t)e->to, &found);
		if (!found) {
			return;
		}
	}
	r_graph_add_edge (di->g, from, to);
}

R_API RGraph *r_graph_dom_tree(RGraph *graph, RGraphNode *root) {
	R_RETURN_VAL_IF_FAIL (graph && root, NULL);
	RGraph *g = r_graph_new ();
	if (!g) {
		return NULL;
	}
	DfsInserter di = { .g = g, .reverse = ht_up_new0 () };
	RVecGraphNodePtr_init (&di.mi);
	if (!di.reverse) {
		RVecGraphNodePtr_fini (&di.mi);
		r_graph_free (g);
		return NULL;
	}
	RGraphVisitor vi = { NULL, NULL, _dfs_ins_edge, NULL, NULL, &di};
	//create a spanning tree
	r_graph_dfs_node (graph, root, &vi);
	if (di.fail) {
		RVecGraphNodePtr_fini (&di.mi);
		ht_up_free (di.reverse);
		r_graph_free (g);
		return NULL;
	}
	while (di.mi_index < RVecGraphNodePtr_length (&di.mi)) {
		RGraphNode *n = *RVecGraphNodePtr_at (&di.mi, di.mi_index++);
		RGraphNode *p = *RVecGraphNodePtr_at (&n->in_nodes, 0);
		if (p && ((RGraphDomNode *)(p->data))->idx == 0) {
			//parent is root node
			continue;
		}
		RGraphDomNode *dn = (RGraphDomNode *)n->data;
		RGraphNode *max_n = NULL, *min_n = NULL;
		RGraphNode **it;
		R_VEC_FOREACH (&dn->node->in_nodes, it) {
			RGraphNode *nn = *it;
			RGraphNode *in = (RGraphNode *)ht_up_find (di.reverse, (ut64)(size_t)nn, NULL);
			if (nn == root) {
				r_graph_del_edge (g, *RVecGraphNodePtr_at (&n->in_nodes, 0), n);
				r_graph_add_edge (g, in, n);
				goto cont;
			}
			if (!max_n || (((RGraphDomNode *)(max_n->data))->idx < ((RGraphDomNode *)(in->data))->idx)) {
				max_n = in;
			}
			if (!min_n || (((RGraphDomNode *)(min_n->data))->idx > ((RGraphDomNode *)(in->data))->idx)) {
				min_n = in;
			}
		}
		while (max_n && ((RGraphDomNode *)max_n->data)->idx > dn->idx) {
			max_n = *RVecGraphNodePtr_at (&max_n->in_nodes, 0);
		}
// at this point max_n refers to the semi dominator (i hope this is correct)
		RGraphNode *dom = min_n;
		while (max_n && ((RGraphDomNode *)max_n->data)->idx < ((RGraphDomNode *)dom->data)->idx) {
			dom = *RVecGraphNodePtr_at (&dom->in_nodes, 0);
		}
// dom <= sdom
		r_graph_del_edge (g, p, n);
		r_graph_add_edge (g, dom, n);
cont:;
	}
	RVecGraphNodePtr_fini (&di.mi);
	ht_up_free (di.reverse);
	RListIter *iter;
	RGraphNode *n;
	r_list_foreach (g->nodes, iter, n) {
		RGraphDomNode *dn = (RGraphDomNode *)n->data;
		n->free = NULL;
		n->data = dn->node;
		free (dn);
	}
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
	if (g) {
		_invert_edges (graph);
	}
	return g;
}
