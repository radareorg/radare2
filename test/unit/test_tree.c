#include <r_util.h>
#include "minunit.h"

void sum_node(RTreeNode *n, RTreeVisitor *vis) {
	int cur = (int)(intptr_t)vis->data;
	vis->data = (void *)(intptr_t)(cur + (int)(intptr_t)n->data);
}

void add_to_list(RTreeNode *n, RTreeVisitor *vis) {
	RList *res = (RList *)vis->data;
	r_list_append(res, n->data);
}

#define check_list(act, exp, descr) do { \
		RListIter *ita = r_list_iterator(act); \
		RListIter *ite = r_list_iterator(exp); \
		while (r_list_iter_next(ita) && r_list_iter_next(ite)) { \
			int a = (int)(intptr_t)r_list_iter_get(ita); \
			int e = (int)(intptr_t)r_list_iter_get(ite); \
			mu_assert_eq (a, e, descr); \
		} \
		mu_assert ("lists must have same elements", (!ita && !ite)); \
	} while (0)

bool test_r_tree() {
	RTreeVisitor calc = { 0 };
	RTreeVisitor lister = { 0 };
	RTree *t = r_tree_new();

	calc.pre_visit = (RTreeNodeVisitCb)sum_node;
	calc.data = (void *)0;

	r_tree_add_node (t, NULL, (void *)1);
	r_tree_bfs(t, &calc);
	mu_assert_eq(1, (int)(intptr_t)calc.data, "calc.data.root");

	r_tree_add_node(t, t->root, (void *)2);
	RTreeNode *s = r_tree_add_node(t, t->root, (void *)3);
	RTreeNode *u = r_tree_add_node(t, t->root, (void *)4);
	calc.data = (void *)0;
	r_tree_bfs(t, &calc);
	mu_assert_eq(10, (int)(intptr_t)calc.data, "calc.data.childs");

	r_tree_add_node(t, s, (void *)5);
	r_tree_add_node(t, s, (void *)10);
	r_tree_add_node(t, u, (void *)11);
	lister.pre_visit = (RTreeNodeVisitCb)add_to_list;

	RList *exp1 = r_list_new();
	r_list_append(exp1, (void *)1);
	r_list_append(exp1, (void *)2);
	r_list_append(exp1, (void *)3);
	r_list_append(exp1, (void *)4);
	r_list_append(exp1, (void *)5);
	r_list_append(exp1, (void *)10);
	r_list_append(exp1, (void *)11);
	lister.data = r_list_new();
	r_tree_bfs(t, &lister);
	check_list((RList *)lister.data, exp1, "lister.bfs");
	r_list_free(exp1);
	r_list_free((RList *)lister.data);

	RList *exp2 = r_list_new();
	r_list_append(exp2, (void *)1);
	r_list_append(exp2, (void *)2);
	r_list_append(exp2, (void *)3);
	r_list_append(exp2, (void *)5);
	r_list_append(exp2, (void *)10);
	r_list_append(exp2, (void *)4);
	r_list_append(exp2, (void *)11);
	lister.data = r_list_new();
	r_tree_dfs(t, &lister);
	check_list((RList *)lister.data, exp2, "lister.preorder");
	r_list_free(exp2);
	r_list_free((RList *)lister.data);


	r_tree_reset(t);
	RTreeNode *root = r_tree_add_node(t, NULL, "root");
	RTreeNode *first = r_tree_add_node(t, root, "first");
	r_tree_add_node(t, root, "second");
	r_tree_add_node(t, root, "third");
	r_tree_add_node(t, first, "f_first");
	r_tree_add_node(t, first, "f_second");

	RList *exp3 = r_list_new();
	r_list_append(exp3, "root");
	r_list_append(exp3, "first");
	r_list_append(exp3, "f_first");
	r_list_append(exp3, "f_second");
	r_list_append(exp3, "second");
	r_list_append(exp3, "third");
	lister.data = r_list_new();
	r_tree_dfs(t, &lister);
	check_list((RList *)lister.data, exp3, "lister.reset.preorder");
	r_list_free(exp3);
	r_list_free((RList *)lister.data);

	r_tree_free(t);
	mu_end;
}

int all_tests() {
	mu_run_test(test_r_tree);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
