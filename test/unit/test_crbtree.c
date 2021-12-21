#include <r_util.h>
#include "minunit.h"

static int cmp_cb(void *incoming, void *in, void *user) {
	int *_incoming = (int *)incoming;
	int *_in = (int *)in;
	return _incoming[0] - _in[0];
}

static RRBTree *create_test_tree(void) {
	int test_data[] = {19, 3, 11, 2, 42, 79, 23, 13, 17, 42};
	RRBTree *tree = r_crbtree_new (free);
	int i;
	for (i = 0; i < (sizeof (test_data) / sizeof (int)); i++) {
		r_crbtree_insert (tree, R_NEWCOPY (int, &test_data[i]), cmp_cb, NULL);
	}
	return tree;
}

static bool test_r_crbtree_in_ascending_order_iteration(void) {
	RRBTree *tree = create_test_tree ();
	RRBNode *node = r_crbtree_first_node (tree);
	int *data = node->data;
	node = r_rbnode_next (node);
	int i = 0;
	bool t = true;
	while (node) {
		int *next_data = node->data;
		i++;
		t &= data[0] <= next_data[0];
		data = next_data;
		node = r_rbnode_next (node);
	}
	mu_assert_true (t, "iteration in ascending order failed");
	mu_assert_eq (i, 9, "iteration over all elements failed");
	r_crbtree_free (tree);
	mu_end;
}

static bool test_r_crbtree_in_ascending_order_iteration2(void) {
	RRBTree *tree = create_test_tree ();
	int s = 17;
	RRBNode *node = r_crbtree_find_node (tree, &s, cmp_cb, NULL);
	mu_assert_neq (node, NULL, "Finding node failed");
	int *data = node->data;
	node = r_rbnode_next (node);
	bool t = true;
	while (node) {
		int *next_data = node->data;
		t &= data[0] <= next_data[0];
		data = next_data;
		node = r_rbnode_next (node);
	}
	mu_assert_true (t, "iteration in ascending order failed");
	r_crbtree_free (tree);
	mu_end;
}

static bool test_r_crbtree_in_descending_order_iteration(void) {
	RRBTree *tree = create_test_tree ();
	RRBNode *node = r_crbtree_last_node (tree);
	int *data = node->data;
	node = r_rbnode_prev (node);
	int i = 0;
	bool t = true;
	while (node) {
		int *prev_data = node->data;
		i++;
		t &= data[0] >= prev_data[0];
		data = prev_data;
		node = r_rbnode_prev (node);
	}
	mu_assert_true (t, "iteration in ascending order failed");
	mu_assert_eq (i, 9, "iteration over all elements failed");
	r_crbtree_free (tree);
	mu_end;
}

static bool test_r_crbtree_in_descending_order_iteration2(void) {
	RRBTree *tree = create_test_tree ();
	int s = 17;
	RRBNode *node = r_crbtree_find_node (tree, &s, cmp_cb, NULL);
	mu_assert_neq (node, NULL, "Finding node failed");
	int *data = node->data;
	node = r_rbnode_prev (node);
	bool t = true;
	while (node) {
		int *prev_data = node->data;
		t &= data[0] >= prev_data[0];
		data = prev_data;
		node = r_rbnode_prev (node);
	}
	mu_assert_true (t, "iteration in descending order failed");
	r_crbtree_free (tree);
	mu_end;
}

static bool test_r_crbtree_delete(void) {
	RRBTree *tree = create_test_tree ();
	int s = 17;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	mu_assert_eq (r_crbtree_find (tree, &s, cmp_cb, NULL), NULL, "deletion failed");
	r_crbtree_free (tree);
	mu_end;
}

static bool test_r_crbtree_in_ascending_order_iteration_after_deletion(void) {
	RRBTree *tree = create_test_tree ();
	RRBNode *node = r_crbtree_first_node (tree);
	int s = 17;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	s = 11;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	s = 3;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	int *data = node->data;
	node = r_rbnode_next (node);
	int i = 0;
	bool t = true;
	while (node) {
		int *next_data = node->data;
		i++;
		t &= data[0] <= next_data[0];
		data = next_data;
		node = r_rbnode_next (node);
	}
	mu_assert_true (t, "iteration in ascending order failed");
	mu_assert_eq (i, 6, "iteration over all elements failed");
	r_crbtree_free (tree);
	mu_end;
}

static bool test_r_crbtree_in_ascending_order_iteration_after_deletion2(void) {
	RRBTree *tree = create_test_tree ();
	int s = 17;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	s = 11;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	s = 3;
	r_crbtree_delete (tree, &s, cmp_cb, NULL);
	s = 2;
	RRBNode *node = r_crbtree_find_node (tree, &s, cmp_cb, NULL);
	int *data = node->data;
	node = r_rbnode_next (node);
	bool t = true;
	while (node) {
		int *next_data = node->data;
		t &= data[0] <= next_data[0];
		data = next_data;
		node = r_rbnode_next (node);
	}
	mu_assert_true (t, "iteration in ascending order failed");
	r_crbtree_free (tree);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_crbtree_in_ascending_order_iteration);
	mu_run_test (test_r_crbtree_in_ascending_order_iteration2);
	mu_run_test (test_r_crbtree_in_descending_order_iteration);
	mu_run_test (test_r_crbtree_in_descending_order_iteration2);
	mu_run_test (test_r_crbtree_delete);
	mu_run_test (test_r_crbtree_in_ascending_order_iteration_after_deletion);
	mu_run_test (test_r_crbtree_in_ascending_order_iteration_after_deletion2);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
