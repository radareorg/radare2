#include <r_util/r_itv.h>
#include "minunit.h"

#define I(begin, end) ((RInterval){begin, end-begin})

int test_r_itv_contain(void) {
	mu_assert ("contain", r_itv_contain (I (0, 3), 0));
	mu_assert ("contain", r_itv_contain (I (0, 3), 2));
	mu_assert ("contain", !r_itv_contain (I (0, 3), 3));
	mu_assert ("contain", r_itv_contain (I (-4, 0), UT64_MAX));
	mu_assert ("contain", !r_itv_contain (I (-4, 0), 0));
	mu_assert ("contain", !r_itv_contain (I (-4, -1), UT64_MAX));
	mu_end;
}

int test_r_itv_include(void) {
	mu_assert ("include", r_itv_include (I (3, 8), I (3, 5)));
	mu_assert ("include", !r_itv_include (I (3, 5), I (2, 4)));
	mu_assert ("include", r_itv_include (I (-4, 0), I (-4, -2)));
	mu_assert ("include", r_itv_include (I (-4, 0), I (-2, 0)));
	mu_assert ("include", r_itv_include (I (-4, 0), I (-1, 0)));
	mu_assert ("include", !r_itv_include (I (-4, 0), I (0, 0)));
	mu_end;
}

int test_r_itv_overlap(void) {
	mu_assert ("overlap", r_itv_overlap (I (3, 5), I (4, 5)));
	mu_assert ("overlap", !r_itv_overlap (I (4, 5), I (3, 4)));
	mu_assert ("overlap", r_itv_overlap (I (4, 0), I (-1, 0)));
	mu_assert ("overlap", !r_itv_overlap (I (4, -1), I (-1, 0)));
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_itv_contain);
	mu_run_test (test_r_itv_include);
	mu_run_test (test_r_itv_overlap);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
