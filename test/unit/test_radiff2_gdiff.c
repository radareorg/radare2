#include <r_util.h>
#include "minunit.h"

static ut8 out[64];
static size_t out_len;

static void print_bytes(const void *p, size_t len, bool big_endian) {
	(void)big_endian;
	memcpy (out + out_len, p, len);
	out_len += len;
}

#include "../../libr/main/radiff2_gdiff.inc.c"

static bool test_copy_splits_after_int_max(void) {
	const ut8 first[] = { 251, 0, 0, 0x7f, 0xff, 0xff, 0xff };
	const ut8 second[] = { 252, 0x7f, 0xff, 0xff, 0xff, 1 };
	out_len = 0;
	gdiff_copy (0, 0x80000000ULL);
	mu_assert_eq (out_len, sizeof (first) + sizeof (second), "two records");
	mu_assert_memeq (out, first, sizeof (first), "COPY(0, INT_MAX)");
	mu_assert_memeq (out + sizeof (first), second, sizeof (second), "COPY(INT_MAX, 1)");
	mu_end;
}

static bool test_copy_64bit_address(void) {
	const ut8 expected[] = { 255, 0, 0, 0, 0, 0x80, 0, 0, 1, 0, 0, 0, 1 };
	out_len = 0;
	gdiff_copy (0x80000001ULL, 0x80000002ULL);
	mu_assert_eq (out_len, sizeof (expected), "one record");
	mu_assert_memeq (out, expected, sizeof (expected), "COPY(0x80000001, 1)");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_copy_splits_after_int_max);
	mu_run_test (test_copy_64bit_address);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
