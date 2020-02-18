#include <r_cons.h>
#include "minunit.h"

bool test_r_cons() {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	const char *foo = "___"; // should crash in asan mode
	r_cons_rgb_parse (foo, &r, &g, &b, &a);

	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 0, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = "\x1b[32mhello\x1b[0m";
	r_cons_rgb_parse (foo, &r, &g, &b, &a);

	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");
	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_cons);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
