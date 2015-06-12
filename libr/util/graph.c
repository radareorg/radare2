/* radare - LGPL - Copyright 2007-2012 - pancake */

#include <r_util.h>

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

R_API RGraphNode *r_graph_get_node (RGraph *t, unsigned int idx) {
	RListIter *it = r_list_find (t->nodes, (void *)(size_t)idx, (RListComparator)node_cmp);
	if (!it)
		return NULL;

	return (RGraphNode *)it->data;
}

R_API RListIter *r_graph_node_iter (RGraph *t, unsigned int idx) {
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

R_API void r_graph_add_edge (RGraph *t, RGraphNode *from, RGraphNode *to) {
	RList *a = get_adjacency (t->adjacency, from->idx);
	if (!a) return;
	r_list_append(a, to);
	t->n_edges++;
}

R_API const RList *r_graph_get_neighbours (RGraph *g, RGraphNode *n) {
	return get_adjacency (g->adjacency, n->idx);
}

R_API RGraphNode *r_graph_nth_neighbour (RGraph *g, RGraphNode *n, int nth) {
	return (RGraphNode *)r_list_get_n (get_adjacency (g->adjacency, n->idx), nth);
}

R_API const RList *r_graph_get_nodes (RGraph *g) {
	return g->nodes;
}

R_API int r_graph_adjacent (RGraph *g, RGraphNode *from, RGraphNode *to) {
	return r_list_contains (get_adjacency (g->adjacency, from->idx), to) ? R_TRUE : R_FALSE;
}
