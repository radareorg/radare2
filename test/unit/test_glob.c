#include <r_util.h>
#include "minunit.h"

bool test_r_glob(void) {
	mu_assert_eq (r_str_glob ("foo.c", "*.c"), 1, "foo.c -> *.c -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "*.d"), 0, "foo.c -> *.d -> 0");
	mu_assert_eq (r_str_glob ("foo.c", "foo*"), 1, "foo.c -> foo* -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "*oo*"), 1, "foo.c -> *oo* -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "*uu*"), 0, "foo.c -> *uu* -> 0");
	mu_assert_eq (r_str_glob ("foo.c", "f*c*"), 1, "foo.c -> f*c* -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "f*c**"), 1, "foo.c -> f*c** -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "f*d"), 0, "foo.c -> f*d -> 0");
	mu_assert_eq (r_str_glob ("foo.c", "*"), 1, "foo.c -> * -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "fo?.c"), 1, "foo.c -> fo?.c -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "^f"), 1, "foo.c -> ^f -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "foo.c$"), 1, "foo.c -> foo.c$ -> 1");
	mu_assert_eq (r_str_glob ("foo.c", "fooooooo"), 0, "foo.c -> fooooooo -> 0");
	mu_end;
}

int all_tests() {
	mu_run_test(test_r_glob);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
