#include <r_util.h>
#include "minunit.h"

bool test_r_str_printf(void) {
	char res[32];
	int count = r_str_printf (res, sizeof (res), "Hello %s", "World");
	mu_assert_streq (res, "Hello World", "truncated string in custom scanf failed");
	mu_assert_eq (count, 11, "return value");

	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_str_printf);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
