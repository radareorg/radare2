#include <r_util.h>
#include <r_bin.h>
#include <r_core.h>
#include "minunit.h"

bool test_r_util(void) {
	char *s = r_str_newf ("Hello %s%d", "test_static", 1);
	mu_assert_streq (s, "Hello test_static1", "r_str_newf should work");
	free (s);
	mu_end;
}

bool test_r_bin(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "bin should be allocated");
	r_bin_free (bin);
	mu_end;
}

bool test_r_core(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "core should be allocated");
	r_core_free (core);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_util);
	mu_run_test (test_r_bin);
	mu_run_test (test_r_core);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
