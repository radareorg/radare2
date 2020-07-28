#include <r_util.h>
#include "minunit.h"

int basic_cmp(const void *a, const void *b) {
	ssize_t sa = (ssize_t)a;
	ssize_t sb = (ssize_t)b;
	return (sa - sb);
}

bool test_basic(void) {
	RBinHeap *bh = r_binheap_new (basic_cmp);
	mu_assert_notnull (bh, "binheap is created");
	mu_assert_true (r_binheap_empty (bh), "binheap is empty");
	r_binheap_push (bh, (void *)(ssize_t)10);
	mu_assert_false (r_binheap_empty (bh), "binheap is not empty anymore");
	r_binheap_clear (bh);
	mu_assert_true (r_binheap_empty (bh), "binheap is empty again after clear");
	r_binheap_free (bh);
	mu_end;
}

bool test_pushpop(void) {
	RBinHeap *bh = r_binheap_new (basic_cmp);
	r_binheap_push (bh, (void *)(ssize_t)10);
	mu_assert_eq ((ssize_t)r_binheap_top (bh), (ssize_t)10, "10 is the top");
	mu_assert_eq ((ssize_t)r_binheap_pop (bh), (ssize_t)10, "10 is popped");
	mu_assert_true (r_binheap_empty (bh), "the only element has been popped out");
	r_binheap_push (bh, (void *)(ssize_t)10);
	r_binheap_push (bh, (void *)(ssize_t)2);
	r_binheap_push (bh, (void *)(ssize_t)5);
	r_binheap_push (bh, (void *)(ssize_t)4);
	r_binheap_push (bh, (void *)(ssize_t)11);
	mu_assert_eq ((ssize_t)r_binheap_top (bh), (ssize_t)2, "2 is the top");
	mu_assert_eq ((ssize_t)r_binheap_pop (bh), (ssize_t)2, "2 is popped");
	mu_assert_eq ((ssize_t)r_binheap_pop (bh), (ssize_t)4, "4 is popped");
	mu_assert_eq ((ssize_t)r_binheap_pop (bh), (ssize_t)5, "5 is popped");
	mu_assert_eq ((ssize_t)r_binheap_pop (bh), (ssize_t)10, "10 is popped");
	mu_assert_eq ((ssize_t)r_binheap_pop (bh), (ssize_t)11, "11 is popped");
	r_binheap_free (bh);
	mu_end;
}

bool all_tests () {
	mu_run_test (test_basic);
	mu_run_test (test_pushpop);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
