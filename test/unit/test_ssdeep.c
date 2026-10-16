#include <r_hash.h>
#include <r_util.h>
#include "minunit.h"

static const char *input_0 = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *input_1 = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXY_";
static const char *input_2 = "abcdefghijklmnopqrstuvwxyz01234567890______GHIJKLMNOPQRSTUVWXY_";

static const char *hash_0 = "3:u+6LO5SfVOjhMvmNKzuu:u+6LO5SfojhMvmNKzuu";
static const char *hash_1 = "3:u+6LO5SfVOjhMvmNKzur:u+6LO5SfojhMvmNKzur";
static const char *hash_2 = "3:u+6LO5SfVOxVmNKzur:u+6LO5SfofmNKzur";

int test_ssdeep(void) {
#define d r_str_distance
	char *h0 = r_hash_ssdeep ((const ut8*)input_0, strlen (input_0));
	char *h1 = r_hash_ssdeep ((const ut8*)input_1, strlen (input_1));
	char *h2 = r_hash_ssdeep ((const ut8*)input_2, strlen (input_2));
	mu_assert_streq (h0, hash_0, "hash0 is fine");
	mu_assert_streq (h1, hash_1, "hash1 is fine");
	mu_assert_streq (h2, hash_2, "hash2 is fine");
	mu_assert_eq (100, d(h0, h0), "distance2");
	mu_assert_eq (95, d(h0, h1), "distance");
	mu_assert_eq (76, d(h0, h2), "distance4");
	mu_assert_eq (95, d(h1, h0), "distance5");
	mu_assert_eq (100, d(h1, h1), "distance6");
	mu_assert_eq (80, d(h1, h2), "distance6");
	mu_assert_eq (80, d(h2, h1), "distance6");
	mu_assert_eq (0, d(h0, "123"), "distance3");
	free (h0);
	free (h1);
	free (h2);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_ssdeep);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
