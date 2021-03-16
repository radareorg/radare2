#include <r_types.h>
#include <r_util.h>
#include "minunit.h"

static int simple_cmp(void *incoming, void *in, void *user) {
	ut32 v[2] = { (ut32)(size_t)incoming, (ut32)(size_t)in };
	return v[0] - v[1];
}

bool test_r_rbtree_cont_foreach_empty() {
	RContRBTree *tree = r_rbtree_cont_new ();
	RBIter alf;
	void *v;
	r_rbtree_cont_foreach (tree, alf, v) {
		mu_assert ("not reachable", false);
	}
	r_rbtree_cont_free (tree);
	mu_end;
}

bool test_r_rbtree_cont_insert() {
	RContRBTree *tree = r_rbtree_cont_new ();
	ut32 i;
	for (i = 0; i < 2000; i++) {
		ut32 v = (ut32)r_num_rand (UT32_MAX >> 1);
		r_rbtree_cont_insert (tree, (void *)(size_t)v, simple_cmp, NULL);
	}
	i = 0;
	bool ret = true;
	void *v;
	RBIter ator;
	r_rbtree_cont_foreach (tree, ator, v) {
		const ut32 next = (ut32)(size_t)v;
		ret &= (i <= next);
		i = next;
	}
	r_rbtree_cont_free (tree);
	mu_assert ("rbtree_cont_insert", ret);
	mu_end;
}

static int strbuf_num_cmp0(void *incoming, void *in, void *user) {
	ut64 v[2] = {
		r_num_get (NULL, r_strbuf_get ((RStrBuf *)incoming)),
		r_num_get (NULL, r_strbuf_get ((RStrBuf *)in))
	};
	return (int)(v[0] - v[1]);
}

static int strbuf_num_cmp1(void *incoming, void *in, void *user) {
	ut64 v[2] = { ((ut64 *)incoming)[0], r_num_get (NULL, r_strbuf_get ((RStrBuf *)in)) };
	return (int)(v[0] - v[1]);
}

bool test_r_rbtree_cont_delete() {
	RContRBTree *tree = r_rbtree_cont_newf ((RContRBFree)r_strbuf_free);
	r_rbtree_cont_insert (tree, r_strbuf_new ("13"), strbuf_num_cmp0, NULL);
	r_rbtree_cont_insert (tree, r_strbuf_new ("0x9090"), strbuf_num_cmp0, NULL);
	r_rbtree_cont_insert (tree, r_strbuf_new ("42"), strbuf_num_cmp0, NULL);
	r_rbtree_cont_insert (tree, r_strbuf_new ("23"), strbuf_num_cmp0, NULL);
	r_rbtree_cont_insert (tree, r_strbuf_new ("0x13373"), strbuf_num_cmp0, NULL);
	ut64 del_me = 0x9090;
	r_rbtree_cont_delete (tree, &del_me, strbuf_num_cmp1, NULL);
	RStrBuf *s;
	RBIter ator;
	bool ret = true;
	r_rbtree_cont_foreach_prev (tree, ator, s) {
		const ut64 v = r_num_get (NULL, r_strbuf_get(s));
		ret &= (v != 0x9090);
	}
	r_rbtree_cont_free (tree);
	mu_assert ("rbtree_cont_delete", ret);
	mu_end;
}

bool test_r_rbtree_cont_node_next() {
	RContRBTree *tree = r_rbtree_cont_new ();
	ut32 i;
	for (i = 0; i < 100; i++) {
		ut32 v = (ut32)r_num_rand (UT32_MAX >> 1);
		r_rbtree_cont_insert (tree, (void *)(size_t)v, simple_cmp, NULL);
	}
	bool ret = true;
	void *v = r_rbtree_cont_first (tree);
	RContRBNode *node = r_rbtree_cont_find_node (tree, v, simple_cmp, NULL);
	i = (ut32)(size_t)v;
	node = r_rbtree_cont_node_next (node);
	mu_assert ("rbtree_cont_node_next no node after first", !!node);
	while (node) {
		const ut32 next = (ut32)(size_t)node->data;
		ret &= (i <= next);
		i = next;
		node = r_rbtree_cont_node_next (node);
	}
	mu_assert ("rbtree_cont_node_next", ret);
	mu_end;
}

bool test_r_rbtree_cont_node_prev() {
	RContRBTree *tree = r_rbtree_cont_new ();
	ut32 i;
	for (i = 0; i < 100; i++) {
		ut32 v = (ut32)r_num_rand (UT32_MAX >> 1);
		r_rbtree_cont_insert (tree, (void *)(size_t)v, simple_cmp, NULL);
	}
	bool ret = true;
	void *v = r_rbtree_cont_last (tree);
	RContRBNode *node = r_rbtree_cont_find_node (tree, v, simple_cmp, NULL);
	i = (ut32)(size_t)v;
	node = r_rbtree_cont_node_prev (node);
	mu_assert ("rbtree_cont_node_prev no node befor last", !!node);
	while (node) {
		const ut32 prev = (ut32)(size_t)node->data;
		ret &= (i >= prev);
		i = prev;
		node = r_rbtree_cont_node_prev (node);
	}
	mu_assert ("rbtree_cont_node_prev", ret);
	mu_end;
}

int main(int argc, char *argv[]) {
	mu_run_test (test_r_rbtree_cont_insert);
	mu_run_test (test_r_rbtree_cont_delete);
	mu_run_test (test_r_rbtree_cont_node_next);
	mu_run_test (test_r_rbtree_cont_node_prev);
	return tests_run != tests_passed;
}
