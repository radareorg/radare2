/* radare - LGPL - Copyright 2007-2023 - pancake, ret2libc, condret */

#include <r_util.h>

enum {
	WHITE_COLOR = 0,
	GRAY_COLOR,
	BLACK_COLOR
};

static RGraphNode *r_graph_node_new(void *data) {
	RGraphNode *p = R_NEW0 (RGraphNode);
	if (p) {
		p->data = data;
		p->free = NULL;
		p->out_nodes = r_list_new ();
		p->in_nodes = r_list_new ();
		p->all_neighbours = r_list_new ();
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
	r_list_free (n->out_nodes);
	r_list_free (n->in_nodes);
	r_list_free (n->all_neighbours);
	free (n);
}

static int node_cmp(unsigned int idx, RGraphNode *b) {
	return idx == b->idx ? 0 : -1;
}

// direction == true => forwards
static void dfs_node(RGraph *g, RGraphNode *n, RGraphVisitor *vis, int color[], const bool direction) {
	if (!n) {
		return;
	}
	RStack *s = r_stack_new (2 * g->n_edges + 1);
	if (!s) {
		return;
	}
	RGraphEdge *edg = R_NEW0 (RGraphEdge);
	if (!edg) {
		r_stack_free (s);
		return;
	}
	edg->from = NULL;
	edg->to = n;
	r_stack_push (s, edg);
	while (!r_stack_is_empty (s)) {
		RGraphEdge *cur_edge = (RGraphEdge *)r_stack_pop (s);
		RGraphNode *v, *cur = cur_edge->to, *from = cur_edge->from;
		RListIter *it;
		int i;

		if (from && cur) {
			if (color[cur->idx] == WHITE_COLOR && vis->tree_edge) {
				vis->tree_edge (cur_edge, vis);
			} else if (color[cur->idx] == GRAY_COLOR && vis->back_edge) {
				vis->back_edge (cur_edge, vis);
			} else if (color[cur->idx] == BLACK_COLOR && vis->fcross_edge) {
				vis->fcross_edge (cur_edge, vis);
			}
		} else if (!cur && from) {
			if (color[from->idx] != BLACK_COLOR && vis->finish_node) {
				vis->finish_node (from, vis);
			}
			color[from->idx] = BLACK_COLOR;
		}
		free (cur_edge);
		if (!cur || color[cur->idx] != WHITE_COLOR) {
			continue;
		}
		if (color[cur->idx] == WHITE_COLOR && vis->discover_node) {
			vis->discover_node (cur, vis);
		}
		color[cur->idx] = GRAY_COLOR;

		edg = R_NEW0 (RGraphEdge);
		if (!edg) {
			break;
		}
		edg->from = cur;
		r_stack_push (s, edg);

		i = 0;
		const RList *neighbours = direction ? cur->out_nodes : cur->in_nodes;
		r_list_foreach (neighbours, it, v) {
			edg = R_NEW (RGraphEdge);
			edg->from = cur;
			edg->to = v;
			edg->nth = i++;
			r_stack_push (s, edg);
		}
	}
	r_stack_free (s);
}

R_API RGraph *r_graph_new(void) {
	RGraph *t = R_NEW0 (RGraph);
	if (!t) {
		return NULL;
	}
	t->nodes = r_list_new ();
	if (!t->nodes) {
		r_graph_free (t);
		return NULL;
	}
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
	if (!t->nodes) {
		return;
	}
	t->nodes->free = (RListFree)r_graph_node_free;
	t->n_nodes = 0; // XXX isnt r_list_length enough?
	t->n_edges = 0;
	t->last_index = 0;
}

R_API RGraphNode *r_graph_add_node(RGraph *t, void *data) {
	r_return_val_if_fail (t && data, NULL);
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
	RListIter *it;
	if (!n) {
		return;
	}
	r_list_foreach (n->in_nodes, it, gn) {
		r_list_delete_data (gn->out_nodes, n);
		r_list_delete_data (gn->all_neighbours, n);
		t->n_edges--;
	}

	r_list_foreach (n->out_nodes, it, gn) {
		r_list_delete_data (gn->in_nodes, n);
		r_list_delete_data (gn->all_neighbours, n);
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
		r_list_insert (from->out_nodes, nth, to);
		r_list_append (from->all_neighbours, to);
		r_list_append (to->in_nodes, from);
		r_list_append (to->all_neighbours, from);
		t->n_edges++;
	}
}

// splits the "split_me", so that new node has it's outnodes
R_API RGraphNode *r_graph_node_split_forward(RGraph *g, RGraphNode *split_me, void *data) {
	RGraphNode *front = r_graph_add_node(g, data);
	RList *tmp = front->out_nodes;
	front->out_nodes = split_me->out_nodes;
	split_me->out_nodes = tmp;
	RListIter *iter;
	RGraphNode *n;
	r_list_foreach (front->out_nodes, iter, n) {
		r_list_delete_data (n->in_nodes, split_me); // optimize me
		r_list_delete_data (n->all_neighbours, split_me); // boy this all_neighbours is so retarding perf here
		r_list_delete_data (split_me->all_neighbours, n);
		r_list_append (n->all_neighbours, front);
		r_list_append (n->in_nodes, front);
		r_list_append (front->all_neighbours, n);
	}
	return front;
}

R_API void r_graph_del_edge(RGraph *t, RGraphNode *from, RGraphNode *to) {
	if (!from || !to || !r_graph_adjacent (t, from, to)) {
		return;
	}
	r_list_delete_data (from->out_nodes, to);
	r_list_delete_data (from->all_neighbours, to);
	r_list_delete_data (to->in_nodes, from);
	r_list_delete_data (to->all_neighbours, from);
	t->n_edges--;
}

// XXX remove comments and static inline all this crap
/* returns the list of nodes reachable from `n` */
R_API const RList *r_graph_get_neighbours(const RGraph *g, const RGraphNode *n) {
	return n? n->out_nodes: NULL;
}

/* returns the n-th nodes reachable from the give node `n`.
 * This, of course, depends on the order of the nodes. */
R_API RGraphNode *r_graph_nth_neighbour(const RGraph *g, const RGraphNode *n, int nth) {
	return n? (RGraphNode *)r_list_get_n (n->out_nodes, nth): NULL;
}

/* returns the list of nodes that can reach `n` */
R_API const RList *r_graph_innodes(const RGraph *g, const RGraphNode *n) {
	return n? n->in_nodes: NULL;
}

/* returns the list of nodes reachable from `n` and that can reach `n`. */
R_API const RList *r_graph_all_neighbours(const RGraph *g, const RGraphNode *n) {
	return n? n->all_neighbours: NULL;
}

R_API const RList *r_graph_get_nodes(const RGraph *g) {
	return g? g->nodes: NULL;
}

/* true if there is an edge from the node `from` to the node `to` */
R_API bool r_graph_adjacent(const RGraph *g, const RGraphNode *from, const RGraphNode *to) {
	if (!g || !from) {
		return false;
	}
	return r_list_contains (from->out_nodes, to);
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
	r_return_if_fail (g && vis);
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
	RList *mi;	//multiple in nodes
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
	if ((r_list_length (n->in_nodes) > 1 ) && (di->idx)) {
		r_list_append (di->mi, node);
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
	r_return_val_if_fail (graph && root, NULL);
	RGraph *g = r_graph_new ();
	if (!g) {
		return NULL;
	}
	DfsInserter di = {g, ht_up_new0 (), r_list_new (), 0, false};
	if (!di.mi) {
		ht_up_free (di.reverse);
		r_graph_free (g);
		return NULL;
	}
	if (!di.reverse) {
		r_list_free (di.mi);
		r_graph_free (g);
		return NULL;
	}
	RGraphVisitor vi = { NULL, NULL, _dfs_ins_edge, NULL, NULL, &di};
	//create a spanning tree
	r_graph_dfs_node (graph, root, &vi);
	if (di.fail) {
		r_list_free (di.mi);
		ht_up_free (di.reverse);
		r_graph_free (g);
		return NULL;
	}
	while (r_list_length (di.mi)) {
		RGraphNode *n = r_list_pop_head (di.mi);
		RGraphNode *p = (RGraphNode *)r_list_get_n (n->in_nodes, 0);
		if (p && ((RGraphDomNode *)(p->data))->idx == 0) {
			//parent is root node
			continue;
		}
		RGraphDomNode *dn = (RGraphDomNode *)n->data;
		RGraphNode *max_n = NULL, *min_n = NULL;
		RListIter *iter;
		RGraphNode *nn;
		r_list_foreach (dn->node->in_nodes, iter, nn) {
			RGraphNode *in = (RGraphNode *)ht_up_find (di.reverse, (ut64)(size_t)nn, NULL);
			if (nn == root) {
				r_graph_del_edge (g, (RGraphNode *)r_list_get_n (n->in_nodes, 0), n);
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
		while (((RGraphDomNode *)max_n->data)->idx > dn->idx) {
			max_n = (RGraphNode *)r_list_get_n (max_n->in_nodes, 0);
		}
// at this point max_n refers to the semi dominator (i hope this is correct)
		RGraphNode *dom = min_n;
		while (((RGraphDomNode *)max_n->data)->idx < ((RGraphDomNode *)dom->data)->idx) {
			dom = (RGraphNode *)r_list_get_n (dom->in_nodes, 0);
		}
// dom <= sdom
		r_graph_del_edge (g, p, n);
		r_graph_add_edge (g, dom, n);
cont:;
	}
	r_list_free (di.mi);
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
		n->in_nodes = (RList *)(((size_t)n->in_nodes) ^ ((size_t)n->out_nodes));
		n->out_nodes = (RList *)(((size_t)n->in_nodes) ^ ((size_t)n->out_nodes));
		n->in_nodes = (RList *)(((size_t)n->in_nodes) ^ ((size_t)n->out_nodes));
	}
}

R_API RGraph *r_graph_pdom_tree(RGraph *graph, RGraphNode *root) {
	r_return_val_if_fail (graph && root, NULL);
	_invert_edges (graph);
	RGraph *g = r_graph_dom_tree (graph, root);
	_invert_edges (graph);
	if (g) {
		_invert_edges (graph);
	}
	return g;
}
