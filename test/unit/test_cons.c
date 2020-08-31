#include <r_cons.h>
#include "minunit.h"

bool test_r_cons() {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	r_cons_rgb_init();

	// all these strdup are for asan/valgrind to have some exact bounds to work with

	char *foo = strdup ("___"); // should crash in asan mode
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 0, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// old school
	foo = strdup ("\x1b[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("32mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 256
	foo = strdup ("\x1b[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 24 bit
	foo = strdup ("\x1b[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// no over-read
	foo = strdup ("38;2");
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("38;5");
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("3");
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_cons);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
