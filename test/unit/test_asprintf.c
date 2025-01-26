#include <r_util.h>
#include "minunit.h"

bool test_r_str_asnprintf (void) {
	// Allocate buffer 1 byte too short.
	size_t buf_size = 11;
	char *res = r_malloc (buf_size);
	int count = r_str_asnprintf (&res, &buf_size, "Hello %s", "World");
	mu_assert_streq (res, "Hello World", "allocating printf failed");
	mu_assert_eq (count, 11, "return value");
	mu_assert_eq (buf_size, 22, "unexpected new buffer size");

	mu_end;
}

bool test_r_str_asprintf (void) {
	char *res = NULL;
	int count = r_str_asprintf (&res, "Hello %s", "World");
	mu_assert_streq (res, "Hello World", "allocating printf failed");
	mu_assert_eq (count, 11, "return value");

	mu_end;
}

bool all_tests (void) {
	mu_run_test (test_r_str_asnprintf);
	mu_run_test (test_r_str_asprintf);
	return tests_passed != tests_run;
}

int main (int argc, char **argv) {
	return all_tests ();
}
