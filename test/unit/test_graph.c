#include <r_util.h>
#include "minunit.h"

static void topo_sorting(RGraphNode *n, RGraphVisitor *vis) {
	RList *order = (RList *)vis->data;
	r_list_prepend (order, n);
}

#define check_list(act, exp, descr) do { \
	RListIter *ita = r_list_iterator (act); \
	RListIter *ite = r_list_iterator (exp); \
	int diff = 0; \
	while (r_list_iter_next (ita) && r_list_iter_next (ite)) { \
		int a = (int)(size_t)r_list_iter_get (ita); \
		int e = (int)(size_t)r_list_iter_get (ite); \
		if (a != e) { \
			eprintf ("[-][%s] test failed (actual: %d; expected: %d)\n", descr, a, e); \
			diff = 1; \
		} \
	} \
	mu_assert_false (ita || ite || diff, "(one list shorter or different)"); \
} while (0)

static bool test_legacy_graph(void) {
	RGraph *g = r_graph_new ();

	mu_assert_eq (g->n_nodes, 0, "n_nodes.start");
	r_graph_add_node (g, (void *)1);
	mu_assert_eq (g->n_nodes, 1, "n_nodes.insert");
	r_graph_reset (g);
	mu_assert_eq (g->n_nodes, 0, "n_nodes.reset");

	RGraphNode *gn = r_graph_add_node (g, (void *)1);
	mu_assert_ptreq (r_graph_get_node (g, gn->idx), gn, "get_node.1");
	RGraphNode *gn2 = r_graph_add_node (g, (void *)2);
	mu_assert_ptreq (r_graph_get_node (g, gn2->idx), gn2, "get_node.2");
	r_graph_add_edge (g, gn, gn2);
	mu_assert_true (r_graph_adjacent (g, gn, gn2), "is_adjacent.1");
	RList *exp_gn_neigh = r_list_new ();
	r_list_append (exp_gn_neigh, gn2);
	check_list (r_graph_get_neighbours (g, gn), exp_gn_neigh, "get_neighbours.1");

	RGraphNode *gn3 = r_graph_add_node (g, (void *)3);
	r_graph_add_edge (g, gn, gn3);
	r_list_append (exp_gn_neigh, gn3);
	check_list (r_graph_get_neighbours (g, gn), exp_gn_neigh, "get_neighbours.2");
	r_list_free (exp_gn_neigh);

	RGraphNode *gn4 = r_graph_add_node (g, (void *)4);
	RGraphNode *gn5 = r_graph_add_node (g, (void *)5);
	RGraphNode *gn6 = r_graph_add_node (g, (void *)6);
	RGraphNode *gn7 = r_graph_add_node (g, (void *)7);
	RGraphNode *gn8 = r_graph_add_node (g, (void *)8);
	RGraphNode *gn9 = r_graph_add_node (g, (void *)9);
	RGraphNode *gn10 = r_graph_add_node (g, (void *)10);
	RList *exp_nodes = r_list_new ();
	r_list_append (exp_nodes, gn);
	r_list_append (exp_nodes, gn2);
	r_list_append (exp_nodes, gn3);
	r_list_append (exp_nodes, gn4);
	r_list_append (exp_nodes, gn5);
	r_list_append (exp_nodes, gn6);
	r_list_append (exp_nodes, gn7);
	r_list_append (exp_nodes, gn8);
	r_list_append (exp_nodes, gn9);
	r_list_append (exp_nodes, gn10);
	const RList *nodes = r_graph_get_nodes (g);
	mu_assert_eq (g->n_nodes, 10, "n_nodes.again");
	check_list (nodes, exp_nodes, "get_all_nodes");
	r_list_free (exp_nodes);

	r_graph_add_edge (g, gn2, gn3);
	r_graph_add_edge (g, gn2, gn4);
	r_graph_add_edge (g, gn2, gn5);
	r_graph_add_edge (g, gn3, gn5);
	r_graph_add_edge (g, gn5, gn7);
	r_graph_add_edge (g, gn7, gn9);
	r_graph_add_edge (g, gn9, gn10);
	r_graph_add_edge (g, gn4, gn6);
	r_graph_add_edge (g, gn6, gn8);
	r_graph_add_edge (g, gn6, gn9);
	r_graph_add_edge (g, gn8, gn10);

	r_graph_add_edge (g, gn5, gn4);
	r_graph_add_edge (g, gn6, gn7);
	r_graph_add_edge (g, gn7, gn8);
	r_graph_add_edge (g, gn8, gn9);
	mu_assert_eq (g->n_edges, 17, "n_edges");
	r_graph_del_edge (g, gn8, gn9);
	mu_assert_eq (r_graph_adjacent (g, gn8, gn9), false, "is_adjacent.0");
	mu_assert_eq (g->n_edges, 16, "n_edges.1");
	r_graph_add_edge (g, gn9, gn8);
	mu_assert_eq (g->n_edges, 17, "n_edges.2");
	mu_assert_eq (r_graph_adjacent (g, gn9, gn8), true, "is_adjacent");
	r_graph_del_edge (g, gn9, gn8);
	r_graph_add_edge (g, gn8, gn9);
	mu_assert_eq (r_graph_adjacent (g, gn9, gn8), false, "is_adjacent.1");
	mu_assert_eq (r_graph_adjacent (g, gn8, gn9), true, "is_adjacent.2");

	RGraphVisitor vis = { 0 };
	vis.data = r_list_new ();
	vis.finish_node = (RGraphNodeCallback)topo_sorting;
	r_graph_dfs_node (g, gn, &vis);
	RList *exp_order = r_list_new ();
	r_list_append (exp_order, gn);
	r_list_append (exp_order, gn2);
	r_list_append (exp_order, gn3);
	r_list_append (exp_order, gn5);
	r_list_append (exp_order, gn4);
	r_list_append (exp_order, gn6);
	r_list_append (exp_order, gn7);
	r_list_append (exp_order, gn8);
	r_list_append (exp_order, gn9);
	r_list_append (exp_order, gn10);
	check_list ((RList *)vis.data, exp_order, "topo_order");
	r_list_free (exp_order);
	r_list_free ((RList *)vis.data);

	RList *exp_innodes = r_list_new ();
	r_list_append (exp_innodes, gn);
	r_list_append (exp_innodes, gn2);
	check_list (r_graph_innodes (g, gn3), exp_innodes, "in_nodes");
	r_list_free (exp_innodes);
	RList *exp_allnodes = r_list_new ();
	r_list_append (exp_allnodes, gn);
	r_list_append (exp_allnodes, gn2);
	r_list_append (exp_allnodes, gn5);
	check_list (r_graph_all_neighbours (g, gn3), exp_allnodes, "in/out_nodes");
	r_list_free (exp_allnodes);

	r_graph_del_node (g, gn);
	r_graph_del_node (g, gn2);
	mu_assert_eq  (g->n_nodes, 8, "n_nodes.del_node");
	mu_assert_eq  (g->n_edges, 12, "n_edges.del_node");

	r_graph_free (g);
	mu_end;
}

static int all_tests() {
	mu_run_test (test_legacy_graph);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
