/* radare - LGPL - Copyright 2007-2012 - pancake */

#include <r_util.h>

enum {
	WHITE_COLOR = 0,
	GRAY_COLOR,
	BLACK_COLOR
};

struct adjacency_t {
	unsigned int idx;
	RList *adj;
};

static RGraphNode *r_graph_node_new (void *data) {
	RGraphNode *p = R_NEW0 (RGraphNode);
	p->data = data;
	p->free = NULL;
	return p;
}

static void r_graph_node_free (RGraphNode *n) {
	if (n->free)
		n->free (n->data);
	free (n);
}

static void adjancency_free (struct adjacency_t *a) {
	r_list_free (a->adj);
	free (a);
}

static int node_cmp (unsigned int idx, RGraphNode *b) {
	return idx == b->idx ? 0 : -1;
}

static int adj_cmp (unsigned int idx, struct adjacency_t *b) {
	return idx == b->idx ? 0 : -1;
}

static RList *get_adjacency (RList *l, unsigned int idx) {
	RListIter *it = r_list_find (l, (void *)(size_t)idx, (RListComparator)adj_cmp);
	if (!it)
		return NULL;

	struct adjacency_t *a = (struct adjacency_t *)it->data;
	return a->adj;
}

static void dfs_node (RGraph *g, RGraphNode *n, RGraphVisitor *vis, int color[]) {
	RStack *s;
	RGraphEdge *edg;

	s = r_stack_new (2 * g->n_edges);

	edg = R_NEW (RGraphEdge);
	edg->from = NULL;
	edg->to = n;
	r_stack_push (s, edg);
	while (!r_stack_is_empty (s)) {
		RGraphEdge *cur_edge = (RGraphEdge *)r_stack_pop (s);
		RGraphNode *v, *cur = cur_edge->to, *from = cur_edge->from;
		const RList *neighbours;
		RListIter *it;

		free (cur_edge);
		if (from && cur) {
			if (color[cur->idx] == WHITE_COLOR && vis->tree_edge)
				vis->tree_edge (from, cur, vis);
			else if (color[cur->idx] == GRAY_COLOR && vis->back_edge)
				vis->back_edge (from, cur, vis);
			else if (color[cur->idx] == BLACK_COLOR && vis->fcross_edge)
				vis->fcross_edge (from, cur, vis);
		} else if (!cur && from) {
			if (color[from->idx] != BLACK_COLOR && vis->finish_node)
				vis->finish_node (from, vis);
			color[from->idx] = BLACK_COLOR;
		}

		if (!cur || color[cur->idx] != WHITE_COLOR)
			continue;

		if (color[cur->idx] == WHITE_COLOR && vis->discover_node)
			vis->discover_node (cur, vis);
		color[cur->idx] = GRAY_COLOR;

		edg = R_NEW (RGraphEdge);
		edg->from = cur;
		edg->to = NULL;
		r_stack_push (s, edg);

		neighbours = r_graph_get_neighbours (g, cur);
		r_list_foreach (neighbours, it, v) {
			edg = R_NEW (RGraphEdge);
			edg->from = cur;
			edg->to = v;
			r_stack_push (s, edg);
		}
	}
	r_stack_free (s);
}

R_API RGraph *r_graph_new () {
	RGraph *t = R_NEW0 (RGraph);
	t->nodes = r_list_new ();
	t->nodes->free = (RListFree)r_graph_node_free;
	t->adjacency = r_list_new ();
	t->adjacency->free = (RListFree)adjancency_free;
	t->n_nodes = 0;
	t->last_index = 0;
	return t;
}

R_API void r_graph_free (RGraph* t) {
	r_list_free (t->nodes);
	r_list_free (t->adjacency);
	free (t);
}

R_API RGraphNode *r_graph_get_node (const RGraph *t, unsigned int idx) {
	RListIter *it = r_list_find (t->nodes, (void *)(size_t)idx, (RListComparator)node_cmp);
	if (!it)
		return NULL;

	return (RGraphNode *)it->data;
}

R_API RListIter *r_graph_node_iter (const RGraph *t, unsigned int idx) {
	return r_list_find (t->nodes, (void *)(size_t)idx, (RListComparator)node_cmp);
}

R_API void r_graph_reset (RGraph *t) {
	r_list_free (t->nodes);
	r_list_free (t->adjacency);

	t->nodes = r_list_new ();
	t->nodes->free = (RListFree)r_graph_node_free;
	t->adjacency = r_list_new ();
	t->adjacency->free = (RListFree)adjancency_free;
	t->n_nodes = 0;
	t->n_edges = 0;
	t->last_index = 0;
}

R_API RGraphNode *r_graph_add_node (RGraph *t, void *data) {
	RGraphNode *n = r_graph_node_new (data);
	struct adjacency_t *a = R_NEW (struct adjacency_t);

	n->idx = t->last_index++;
	r_list_append (t->nodes, n);
	a->idx = n->idx;
	a->adj = r_list_new ();
	r_list_append (t->adjacency, a);
	t->n_nodes++;
	return n;
}

/* remove the node from the graph and free the node */
/* users of this function should be aware they can't access n anymore */
R_API void r_graph_del_node (RGraph *t, RGraphNode *n) {
	RGraphNode *gn;
	RListIter *it;

	r_list_foreach (t->nodes, it, gn) {
		RList *neigh = get_adjacency (t->adjacency, gn->idx);
		int deleted = r_list_delete_data (neigh, n);
		if (deleted)
			t->n_edges--;
	}

	it = r_list_find (t->adjacency, (void *)(size_t)n->idx, (RListComparator)adj_cmp);
	if (it) {
		struct adjacency_t *a = (struct adjacency_t *)it->data;
		int adj_len = r_list_length (a->adj);
		r_list_delete (t->adjacency, it);
		t->n_edges -= adj_len;
	}
	r_list_delete_data (t->nodes, n);
	t->n_nodes--;
}

R_API void r_graph_add_edge (RGraph *t, RGraphNode *from, RGraphNode *to) {
	RList *a = get_adjacency (t->adjacency, from->idx);
	if (!a) return;
	r_list_append(a, to);
	t->n_edges++;
}

R_API void r_graph_del_edge (RGraph *t, RGraphNode *from, RGraphNode *to) {
	RList *a = get_adjacency (t->adjacency, from->idx);
	if (!a) return;
	r_list_delete_data (a, to);
	t->n_edges--;
}

R_API const RList *r_graph_get_neighbours (const RGraph *g, const RGraphNode *n) {
	return get_adjacency (g->adjacency, n->idx);
}

R_API RGraphNode *r_graph_nth_neighbour (const RGraph *g, const RGraphNode *n, int nth) {
	return (RGraphNode *)r_list_get_n (get_adjacency (g->adjacency, n->idx), nth);
}

R_API const RList *r_graph_get_nodes (const RGraph *g) {
	return g->nodes;
}

R_API int r_graph_adjacent (const RGraph *g, const RGraphNode *from, const RGraphNode *to) {
	return r_list_contains (get_adjacency (g->adjacency, from->idx), to) ? R_TRUE : R_FALSE;
}

R_API void r_graph_dfs_node (RGraph *g, RGraphNode *n, RGraphVisitor *vis) {
	int *color;

	if (!g || !n || !vis) return;
	color = R_NEWS0 (int, g->last_index);
	dfs_node (g, n, vis, color);
	free (color);
}

R_API void r_graph_dfs (RGraph *g, RGraphVisitor *vis) {
	RGraphNode *n;
	RListIter *it;
	int *color;

	if (!g || !vis) return;
	color = R_NEWS0 (int, g->last_index);
	r_list_foreach (g->nodes, it, n) {
		 if (color[n->idx] == WHITE_COLOR)
			 dfs_node (g, n, vis, color);
	}
	free (color);
}
