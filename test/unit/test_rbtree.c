#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <r_util.h>
#include "minunit.h"

static void random_iota(int *a, int n) {
	int i;
	a[0] = 0;
	for (i = 1; i < n; i++) {
		int x = rand () % (i + 1);
		if (i != x) {
			a[i] = a[x];
		}
		a[x] = i;
	}
}

struct Node {
	int key;
	int size; // subtree size
	RBNode rb; // intrusive red-black tree node
};

static void freefn(RBNode *a, void *user) {
	free (container_of (a, struct Node, rb));
}

static void size(RBNode *a_) {
	int i;
	struct Node *a = container_of (a_, struct Node, rb);
	a->size = 1;
	for (i = 0; i < 2; i++) {
		if (a_->child[i]) {
			a->size += container_of (a_->child[i], struct Node, rb)->size;
		}
	}
}

static int cmp(const void *a, const RBNode *b, void *user) {
	return ((const struct Node *)a)->key - container_of (b, const struct Node, rb)->key;
}

static struct Node *make(int key) {
	struct Node *x = R_NEW (struct Node);
	x->key = key;
	return x;
}

static bool check1(RBNode *x, int dep, int black, bool leftmost) {
	static int black_;
	if (x) {
		black += !x->red;
		if (x->red && ((x->child[0] && x->child[0]->red) || (x->child[1] && x->child[1]->red))) {
			printf ("error: red violation\n");
			return false;
		}
		if ((x->child[0] ? container_of (x->child[0], struct Node, rb)->size : 0) +
				(x->child[1] ? container_of (x->child[1], struct Node, rb)->size : 0) + 1 !=
				container_of (x, struct Node, rb)->size) {
			printf ("error: size violation\n");
			return false;
		}
		if (!check1 (x->child[0], dep + 1, black, leftmost)) {
			return false;
		}
		if (!check1 (x->child[1], dep + 1, black, false)) {
			return false;
		}
	} else if (leftmost) {
		black_ = black;
	} else if (black_ != black) {
		printf ("error: different black height\n");
		return false;
	}
	return true;
}

bool check(RBNode *tree) {
	return check1 (tree, 0, 0, true);
}

bool test_r_rbtree_bound_iterate() {
	struct Node key = { 0 };
	RBIter it;
	RBNode *tree = NULL;
	struct Node *x;
	int i;

	RBIter f = r_rbtree_first (tree);
	mu_assert_eq (f.len, 0, "iter with 0 length");

	for (i = 0; i < 99; i++) {
		x = make (i * 2);
		r_rbtree_insert (&tree, x, &x->rb, cmp, NULL);
	}

	// lower_bound
	key.key = 0x24;
	it = r_rbtree_lower_bound_forward (tree, &key, cmp, NULL);
	i = 0x24;
	r_rbtree_iter_while (it, x, struct Node, rb) {
		mu_assert_eq (x->key, i, "lower_bound_forward equal");
		i += 2;
	}
	mu_assert_eq (i - 2, 98 * 2, "lower_bound_forward complete");

	key.key = 0x25;
	it = r_rbtree_lower_bound_forward (tree, &key, cmp, NULL);
	i = 0x26;
	r_rbtree_iter_while (it, x, struct Node, rb) {
		mu_assert_eq (x->key, i, "lower_bound_forward more");
		i += 2;
	}
	mu_assert_eq (i - 2, 98 * 2, "lower_bound_forward complete");

	// upper_bound
	key.key = 0x24;
	it = r_rbtree_upper_bound_backward (tree, &key, cmp, NULL);
	i = 0x24;
	r_rbtree_iter_while_prev (it, x, struct Node, rb) {
		mu_assert_eq (x->key, i, "upper_bound_backward");
		i -= 2;
	}
	mu_assert_eq (i + 2, 0, "upper_bound_backward complete");

	key.key = 0x25;
	it = r_rbtree_upper_bound_backward (tree, &key, cmp, NULL);
	i = 0x24;
	r_rbtree_iter_while_prev (it, x, struct Node, rb) {
		mu_assert_eq (x->key, i, "upper_bound_backward less");
		i -= 2;
	}
	mu_assert_eq (i + 2, 0, "upper_bound_backward complete");

	r_rbtree_free (tree, freefn, NULL);
	mu_end;
}

bool test_r_rbtree_bound() {
	struct Node key = { 0 };
	RBIter it;
	RBNode *tree = NULL;
	struct Node *x;
	int i;

	for (i = 0; i < 99; i++) {
		x = make (i*2);
		r_rbtree_insert (&tree, x, &x->rb, cmp, NULL);
	}

	key.key = 0x24;
	x = container_of (r_rbtree_lower_bound (tree, &key, cmp, NULL), struct Node, rb);
	mu_assert_eq (x->key, 0x24, "lower bound equal");

	key.key = 0x25;
	x = container_of (r_rbtree_lower_bound (tree, &key, cmp, NULL), struct Node, rb);
	mu_assert_eq (x->key, 0x26, "lower bound more");

	key.key = 0x24;
	x = container_of (r_rbtree_upper_bound (tree, &key, cmp, NULL), struct Node, rb);
	mu_assert_eq (x->key, 0x24, "upper bound equal");

	key.key = 0x25;
	x = container_of (r_rbtree_upper_bound (tree, &key, cmp, NULL), struct Node, rb);
	mu_assert_eq (x->key, 0x24, "upper bound less");

	mu_end;
}

static bool insert_delete(int *a, int n, RBNodeSum sum) {
	RBNode *tree = NULL;
	struct Node *x;
	int i, t;

	for (i = 0; i < n; i++) {
		x = make (a[i]);
		r_rbtree_aug_insert (&tree, x, &x->rb, cmp, NULL, sum);
		if (sum) {
			mu_assert_eq (i + 1, container_of (tree, struct Node, rb)->size, "size");
			mu_assert ("shape", check (tree));
		}
	}

	random_iota (a, n);
	for (i = 0; i < n; i++) {
		struct Node x = {.key = a[i]};
		t = r_rbtree_aug_delete (&tree, &x, cmp, NULL, freefn, NULL, sum);
		mu_assert ("delete", t);
		t = r_rbtree_aug_delete (&tree, &x, cmp, NULL, freefn, NULL, sum);
		mu_assert ("delete non-existent", !t);
		if (sum) {
			if (i == n-1)
				mu_assert ("size", tree == NULL);
			else
				mu_assert_eq (n - i - 1, container_of (tree, struct Node, rb)->size, "size");
			mu_assert ("shape", check (tree));
		}
	}

	r_rbtree_free (tree, freefn, NULL);
	return MU_PASSED;
}

bool test_r_rbtree_insert_delete(void) {
#define N 1000
	int a[N], i;

	// Random
	random_iota (a, N);
	insert_delete (a, N, NULL);

	// Increasing
	for (i = 0; i < N; i++)
		a[i] = i;
	insert_delete (a, N, NULL);

	// Decreasing
	for (i = 0; i < N; i++)
		a[i] = N - 1 - i;
	insert_delete (a, N, NULL);

	mu_end;
#undef N
}

bool test_r_rbtree_augmented_insert_delete(void) {
#define N 1000
	int a[N], i;

	// Random
	random_iota (a, N);
	insert_delete (a, N, size);

	// Increasing
	for (i = 0; i < N; i++)
		a[i] = i;
	insert_delete (a, N, size);

	// Decreasing
	for (i = 0; i < N; i++)
		a[i] = N - 1 - i;
	insert_delete (a, N, size);

	mu_end;
#undef N
}

bool test_r_rbtree_augmented_insert_delete2(void) {
#define N 1000
	RBNode *tree = NULL;
	struct Node *x;
	int a[N], i, t;

	// Random
	random_iota (a, N);
	for (i = 0; i < N; i++) {
		x = make (a[i] * 2);
		r_rbtree_aug_insert (&tree, x, &x->rb, cmp, NULL, size);
	}
	for (i = 0; i < N; i++) {
		struct Node x = {.key = a[i] * 2 + 1};
		t = r_rbtree_aug_delete (&tree, &x, cmp, NULL, freefn, NULL, size);
		mu_assert ("delete non-existent", !t);
		mu_assert_eq (N - i, container_of (tree, struct Node, rb)->size, "size");
		mu_assert ("shape", check (tree));

		x.key = a[i] * 2;
		t = r_rbtree_aug_delete (&tree, &x, cmp, NULL, freefn, NULL, size);
		mu_assert ("delete", t);
		mu_assert ("shape", check (tree));
	}

	mu_end;
#undef N
}

bool test_r_rbtree_traverse(void) {
	RBIter it;
	RBNode *tree = NULL;
	struct Node *x;
	int i;

	for (i = 0; i < 99; i++) {
		x = make (i);
		r_rbtree_insert (&tree, x, &x->rb, cmp, NULL);
	}
	i = 0;
	r_rbtree_foreach (tree, it, x, struct Node, rb) {
		mu_assert_eq (i, x->key, "foreach");
		i++;
	}
	r_rbtree_foreach_prev (tree, it, x, struct Node, rb) {
		i--;
		mu_assert_eq (i, x->key, "foreach_prev");
	}

	r_rbtree_free (tree, freefn, NULL);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_rbtree_bound);
	mu_run_test (test_r_rbtree_bound_iterate);
	mu_run_test (test_r_rbtree_insert_delete);
	mu_run_test (test_r_rbtree_traverse);
	mu_run_test (test_r_rbtree_augmented_insert_delete);
	mu_run_test (test_r_rbtree_augmented_insert_delete2);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
