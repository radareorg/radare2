/* radare - LGPL - Copyright 2007-2012 - pancake */

#include <r_util.h>

#define INITIAL_CAPACITY 16

/* TODO: allow deletion of nodes and update the "is_in_range"
 *       function to "is_valid_index" function, that checks if
 *       the node really exists */
static int is_in_range (RGraph *g, unsigned int idx) {
	return idx < g->n_nodes;
}

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

R_API RGraph *r_graph_new () {
	RGraph *t = R_NEW0 (RGraph);
	t->capacity = INITIAL_CAPACITY;
	t->nodes = R_NEWS0 (RGraphNode *, t->capacity);
	t->adjacency = R_NEWS0 (RList *, t->capacity);
	t->n_nodes = 0;
	t->last_index = -1;
	return t;
}

R_API void r_graph_free (RGraph* t) {
	unsigned i;

	for (i = 0; i < t->capacity; ++i) {
		if (t->nodes[i] != NULL) {
			r_list_free (t->adjacency[i]);
			r_graph_node_free (t->nodes[i]);
		}
	}

	free (t->nodes);
	free (t->adjacency);
	free (t);
}

R_API RGraphNode *r_graph_get_node (RGraph *t, unsigned int idx) {
	return t->nodes[idx];
}

R_API void r_graph_reset (RGraph *t) {
	unsigned i;

	for (i = 0; i < t->capacity; ++i) {
		if (t->adjacency[i])
			r_list_free (t->adjacency[i]);
		if (t->nodes[i])
			r_graph_node_free (t->nodes[i]);
	}
	free (t->nodes);
	t->capacity = INITIAL_CAPACITY;
	t->nodes = R_NEWS0 (RGraphNode *, t->capacity);
	t->adjacency = R_NEWS0 (RList *, t->capacity);
	t->n_nodes = 0;
}

R_API RGraphNode *r_graph_add_node (RGraph *t, void *data) {
	RGraphNode *n = r_graph_node_new (data);

	if (t->n_nodes == t->capacity) {
		int new_capacity = t->capacity * 2;
		t->adjacency = realloc (t->adjacency, new_capacity * sizeof(RList *));
		t->nodes = realloc (t->nodes, new_capacity * sizeof (RGraphNode *));
		memset (t->nodes + t->capacity, 0, (new_capacity - t->capacity) * sizeof (RGraphNode *));
		t->capacity = new_capacity;
	}

	n->idx = ++t->last_index;
	t->adjacency[n->idx] = r_list_new();
	t->adjacency[n->idx]->free = NULL;
	t->nodes[n->idx] = n;
	t->n_nodes++;
	return n;
}

R_API void r_graph_add_edge (RGraph *t, RGraphNode *from, RGraphNode *to) {
	if (is_in_range(t, from->idx))
		r_list_append(t->adjacency[from->idx], to);
}

R_API RList *r_graph_get_neighbours (RGraph *g, RGraphNode *n) {
	return is_in_range(g, n->idx) ? g->adjacency[n->idx] : NULL;
}

/* returns a list with all the nodes in the graph
 * NOTE: the user should free the list */
R_API RList *r_graph_get_nodes (RGraph *g) {
	RList *res;
	unsigned int i;

	res = r_list_new ();
	res->free = NULL;
	for (i = 0; i < g->capacity; ++i)
		if (g->nodes[i])
			r_list_append (res, g->nodes[i]);
	return res;
}

R_API int r_graph_adjacent (RGraph *g, RGraphNode *from, RGraphNode *to) {
	return r_list_contains (g->adjacency[from->idx], to) ? R_TRUE : R_FALSE;
}
