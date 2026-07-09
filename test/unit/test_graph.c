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

static bool check_vec(const RVecGraphNodePtr *act, const RVecGraphNodePtr *exp, const char *descr) {
	size_t alen = RVecGraphNodePtr_length (act);
	size_t elen = RVecGraphNodePtr_length (exp);
	bool diff = alen != elen;
	size_t i;
	for (i = 0; i < R_MIN (alen, elen); i++) {
		RGraphNode *a = *RVecGraphNodePtr_at (act, i);
		RGraphNode *e = *RVecGraphNodePtr_at (exp, i);
		if (a != e) {
			eprintf ("[-][%s] test failed (actual: %p; expected: %p)\n", descr, (void *)a, (void *)e);
			diff = true;
		}
	}
	return !diff;
}

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
	RVecGraphNodePtr exp_gn_neigh;
	RVecGraphNodePtr_init (&exp_gn_neigh);
	RVecGraphNodePtr_push_back (&exp_gn_neigh, &gn2);
	mu_assert_true (check_vec (r_graph_get_neighbours (g, gn), &exp_gn_neigh, "get_neighbours.1"), "(one vector shorter or different)");

	RGraphNode *gn3 = r_graph_add_node (g, (void *)3);
	r_graph_add_edge (g, gn, gn3);
	RVecGraphNodePtr_push_back (&exp_gn_neigh, &gn3);
	mu_assert_true (check_vec (r_graph_get_neighbours (g, gn), &exp_gn_neigh, "get_neighbours.2"), "(one vector shorter or different)");
	RVecGraphNodePtr_fini (&exp_gn_neigh);

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

	RGraphVisitor vis = {0};
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

	RVecGraphNodePtr exp_innodes;
	RVecGraphNodePtr_init (&exp_innodes);
	RVecGraphNodePtr_push_back (&exp_innodes, &gn);
	RVecGraphNodePtr_push_back (&exp_innodes, &gn2);
	mu_assert_true (check_vec (r_graph_innodes (g, gn3), &exp_innodes, "in_nodes"), "(one vector shorter or different)");
	RVecGraphNodePtr_fini (&exp_innodes);
	RVecGraphNodePtr exp_allnodes;
	RVecGraphNodePtr_init (&exp_allnodes);
	RVecGraphNodePtr_push_back (&exp_allnodes, &gn);
	RVecGraphNodePtr_push_back (&exp_allnodes, &gn2);
	RVecGraphNodePtr_push_back (&exp_allnodes, &gn5);
	mu_assert_true (check_vec (r_graph_all_neighbours (g, gn3), &exp_allnodes, "in/out_nodes"), "(one vector shorter or different)");
	RVecGraphNodePtr_fini (&exp_allnodes);

	r_graph_del_node (g, gn);
	r_graph_del_node (g, gn2);
	mu_assert_eq  (g->n_nodes, 8, "n_nodes.del_node");
	mu_assert_eq  (g->n_edges, 12, "n_edges.del_node");

	r_graph_free (g);
	mu_end;
}

#define DOM_MAXN 32

typedef struct {
	RGraph *g;
	RGraphNode *n[DOM_MAXN];
	size_t count;
} DomTestGraph;

static void dom_graph_init(DomTestGraph *tg, size_t count) {
	tg->g = r_graph_new ();
	tg->count = count;
	size_t i;
	for (i = 0; i < count; i++) {
		tg->n[i] = r_graph_add_node (tg->g, (void *)(size_t)(i + 1));
	}
}

// edges are (from, to) pairs terminated by -1
static void dom_graph_edges(DomTestGraph *tg, const int *edges) {
	size_t i;
	for (i = 0; edges[i] >= 0; i += 2) {
		r_graph_add_edge (tg->g, tg->n[edges[i]], tg->n[edges[i + 1]]);
	}
}

static size_t dom_node_index(RGraphNode *const *nodes, size_t n, const RGraphNode *x) {
	size_t i;
	for (i = 0; i < n; i++) {
		if (nodes[i] == x) {
			return i;
		}
	}
	return SZT_MAX;
}

static ut64 dom_reachable(RGraphNode *const *nodes, size_t n, size_t root) {
	ut64 reach = 1ULL << root;
	size_t stack[DOM_MAXN];
	size_t sp = 0;
	stack[sp++] = root;
	while (sp) {
		size_t v = stack[--sp];
		RGraphNode **it;
		R_VEC_FOREACH (&nodes[v]->out_nodes, it) {
			size_t w = dom_node_index (nodes, n, *it);
			if (!(reach & (1ULL << w))) {
				reach |= 1ULL << w;
				stack[sp++] = w;
			}
		}
	}
	return reach;
}

// brute-force iterative-dataflow oracle; idom[i] = i for the root, SZT_MAX if unreachable
static void dom_oracle(RGraphNode *const *nodes, size_t n, size_t root, size_t *idom) {
	ut64 reach = dom_reachable (nodes, n, root);
	ut64 dom[DOM_MAXN];
	size_t i, j;
	for (i = 0; i < n; i++) {
		dom[i] = (i == root)? (1ULL << i): reach;
	}
	bool changed = true;
	while (changed) {
		changed = false;
		for (i = 0; i < n; i++) {
			if (i == root || !(reach & (1ULL << i))) {
				continue;
			}
			ut64 d = reach;
			RGraphNode **it;
			R_VEC_FOREACH (&nodes[i]->in_nodes, it) {
				size_t p = dom_node_index (nodes, n, *it);
				if (reach & (1ULL << p)) {
					d &= dom[p];
				}
			}
			d |= 1ULL << i;
			if (d != dom[i]) {
				dom[i] = d;
				changed = true;
			}
		}
	}
	for (i = 0; i < n; i++) {
		if (!(reach & (1ULL << i))) {
			idom[i] = SZT_MAX;
			continue;
		}
		if (i == root) {
			idom[i] = i;
			continue;
		}
		// strict dominators are totally ordered; the immediate one has the largest dominator set
		size_t best = SZT_MAX;
		for (j = 0; j < n; j++) {
			if (j == i || !(dom[i] & (1ULL << j))) {
				continue;
			}
			if (best == SZT_MAX || r_bits_popcount64 (dom[j]) > r_bits_popcount64 (dom[best])) {
				best = j;
			}
		}
		idom[i] = best;
	}
}

static bool dom_tree_check(DomTestGraph *tg, size_t root, const char *descr) {
	size_t idom[DOM_MAXN];
	size_t i, n = tg->count;
	dom_oracle (tg->n, n, root, idom);
	RGraph *t = r_graph_dom_tree (tg->g, tg->n[root]);
	if (!t) {
		eprintf ("[-][%s] dom tree is NULL\n", descr);
		return false;
	}
	bool ok = true;
	RGraphNode *tnodes[DOM_MAXN] = {0};
	RListIter *it;
	RGraphNode *tn;
	r_list_foreach (t->nodes, it, tn) {
		size_t oi = dom_node_index (tg->n, n, (RGraphNode *)tn->data);
		if (oi == SZT_MAX) {
			eprintf ("[-][%s] tree node data is not a node of the input graph\n", descr);
			ok = false;
			continue;
		}
		if (tnodes[oi]) {
			eprintf ("[-][%s] duplicated tree node for %u\n", descr, (ut32)oi);
			ok = false;
		}
		tnodes[oi] = tn;
	}
	for (i = 0; i < n; i++) {
		if (idom[i] == SZT_MAX) {
			if (tnodes[i]) {
				eprintf ("[-][%s] unreachable node %u is in the tree\n", descr, (ut32)i);
				ok = false;
			}
			continue;
		}
		if (!tnodes[i]) {
			eprintf ("[-][%s] reachable node %u is missing from the tree\n", descr, (ut32)i);
			ok = false;
			continue;
		}
		size_t nin = RVecGraphNodePtr_length (&tnodes[i]->in_nodes);
		if (i == root) {
			if (nin) {
				eprintf ("[-][%s] root has %u parents\n", descr, (ut32)nin);
				ok = false;
			}
			continue;
		}
		if (nin != 1) {
			eprintf ("[-][%s] node %u has %u parents\n", descr, (ut32)i, (ut32)nin);
			ok = false;
			continue;
		}
		RGraphNode *parent = *RVecGraphNodePtr_at (&tnodes[i]->in_nodes, 0);
		size_t pi = dom_node_index (tg->n, n, (RGraphNode *)parent->data);
		if (pi != idom[i]) {
			eprintf ("[-][%s] idom(%u) is %u, expected %u\n", descr, (ut32)i, (ut32)pi, (ut32)idom[i]);
			ok = false;
		}
	}
	r_graph_free (t);
	return ok;
}

static bool test_dom_tree_linear(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 3);
	const int edges[] = { 0, 1, 1, 2, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "linear"), "linear chain idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_diamond(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 4);
	const int edges[] = { 0, 1, 0, 2, 1, 3, 2, 3, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "diamond"), "diamond idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_nested_loops(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 6);
	// 1 is the outer loop header, 2 the inner one; 3->2 and 4->1 are the back edges
	const int edges[] = { 0, 1, 1, 2, 2, 3, 3, 2, 2, 4, 3, 4, 4, 1, 4, 5, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "nested_loops"), "nested loop idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_irreducible(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 4);
	// two-entry loop between 1 and 2; only the root dominates 1, 2 and 3
	const int edges[] = { 0, 1, 0, 2, 1, 2, 2, 1, 1, 3, 2, 3, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "irreducible"), "irreducible loop idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_self_loop(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 3);
	const int edges[] = { 0, 1, 1, 1, 1, 2, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "self_loop"), "self loop idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_back_to_root(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 3);
	const int edges[] = { 0, 1, 1, 0, 1, 2, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "back_to_root"), "back edge to root idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_unreachable_node(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 5);
	// node 4 is disconnected and must not appear in the tree
	const int edges[] = { 0, 1, 0, 2, 1, 3, 2, 3, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "unreachable_node"), "unreachable node idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_unreachable_pred(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 4);
	// 3 is unreachable but is a predecessor of the join node 2
	const int edges[] = { 0, 1, 1, 2, 3, 2, -1 };
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "unreachable_pred"), "unreachable predecessor idoms");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_single_node(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 1);
	mu_assert_true (dom_tree_check (&tg, 0, "single_node"), "single node tree");
	r_graph_free (tg.g);
	mu_end;
}

static bool test_dom_tree_dense(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 12);
	// mix of joins, cross edges, back edges and an irreducible region
	const int edges[] = {
		0, 1, 0, 2, 1, 3, 2, 3, 2, 4, 3, 5, 4, 5, 4, 6, 5, 7, 6, 7,
		7, 8, 8, 9, 9, 8, 9, 10, 10, 2, 3, 11, 10, 11, 6, 11, 5, 6, 8, 3, -1
	};
	dom_graph_edges (&tg, edges);
	mu_assert_true (dom_tree_check (&tg, 0, "dense"), "dense graph idoms");
	r_graph_free (tg.g);
	mu_end;
}

static ut32 dom_rng_state = 0x2545f491;

static ut32 dom_rng(void) {
	ut32 x = dom_rng_state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	dom_rng_state = x;
	return x;
}

static bool test_dom_tree_random_sweep(void) {
	size_t iter;
	for (iter = 0; iter < 500; iter++) {
		DomTestGraph tg;
		const size_t n = 2 + (dom_rng () % 15);
		dom_graph_init (&tg, n);
		// random density from sparse chains to multigraphs with self loops
		const size_t m = dom_rng () % (3 * n);
		size_t k;
		for (k = 0; k < m; k++) {
			r_graph_add_edge (tg.g, tg.n[dom_rng () % n], tg.n[dom_rng () % n]);
		}
		char descr[32];
		snprintf (descr, sizeof (descr), "random_sweep_%u", (ut32)iter);
		const bool ok = dom_tree_check (&tg, 0, descr);
		r_graph_free (tg.g);
		mu_assert_true (ok, "random sweep idoms match the oracle");
	}
	mu_end;
}

static bool test_pdom_tree(void) {
	DomTestGraph tg;
	dom_graph_init (&tg, 4);
	const int edges[] = { 0, 1, 0, 2, 1, 3, 2, 3, -1 };
	dom_graph_edges (&tg, edges);
	RGraph *t = r_graph_pdom_tree (tg.g, tg.n[3]);
	mu_assert_notnull (t, "pdom tree");
	RGraphNode *tnodes[DOM_MAXN] = {0};
	RListIter *it;
	RGraphNode *tn;
	r_list_foreach (t->nodes, it, tn) {
		size_t oi = dom_node_index (tg.n, tg.count, (RGraphNode *)tn->data);
		mu_assert_neq ((ut64)oi, (ut64)SZT_MAX, "pdom node maps to the input graph");
		tnodes[oi] = tn;
	}
	size_t i;
	for (i = 0; i < 3; i++) {
		mu_assert_notnull (tnodes[i], "node in pdom tree");
		mu_assert_eq (RVecGraphNodePtr_length (&tnodes[i]->in_nodes), 1, "single pdom parent");
		RGraphNode *parent = *RVecGraphNodePtr_at (&tnodes[i]->in_nodes, 0);
		mu_assert_ptreq (parent->data, tg.n[3], "ipdom is the exit node");
	}
	r_graph_free (t);
	// the input graph must come back with its original orientation
	mu_assert_eq (tg.g->n_edges, 4, "input edge count preserved");
	mu_assert_true (r_graph_adjacent (tg.g, tg.n[0], tg.n[1]), "input edge 0->1 preserved");
	mu_assert_true (r_graph_adjacent (tg.g, tg.n[1], tg.n[3]), "input edge 1->3 preserved");
	mu_assert_false (r_graph_adjacent (tg.g, tg.n[1], tg.n[0]), "input graph not inverted");
	mu_assert_false (r_graph_adjacent (tg.g, tg.n[3], tg.n[1]), "input graph not inverted");
	r_graph_free (tg.g);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_legacy_graph);
	mu_run_test (test_dom_tree_linear);
	mu_run_test (test_dom_tree_diamond);
	mu_run_test (test_dom_tree_nested_loops);
	mu_run_test (test_dom_tree_irreducible);
	mu_run_test (test_dom_tree_self_loop);
	mu_run_test (test_dom_tree_back_to_root);
	mu_run_test (test_dom_tree_unreachable_node);
	mu_run_test (test_dom_tree_unreachable_pred);
	mu_run_test (test_dom_tree_single_node);
	mu_run_test (test_dom_tree_dense);
	mu_run_test (test_dom_tree_random_sweep);
	mu_run_test (test_pdom_tree);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
