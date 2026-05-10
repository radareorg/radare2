#include <r_util.h>
#include "minunit.h"

bool test_r_bitmap_set(void) {
	int i;
	const int max_value = (2343 + 1);
	const ut32 values [] = { 1, 2, 3, 4, 8, 34, 543, 2343 };
	const int len = sizeof (values) / sizeof (ut32);
	RBitmap *bitmap = r_bitmap_new (max_value);
	for (i = 0; i < len; i++) {
		r_bitmap_set (bitmap, values[i]);
	}
	for (i = 0; i < len; i++) {
		mu_assert_eq (r_bitmap_test (bitmap, values[i]), true,
				"Bit should be set.");
	}
	for (i = 0; i < len; i++) {
		r_bitmap_unset (bitmap, values[i]);
	}
	for (i = 0; i < len; i++) {
		mu_assert_eq (r_bitmap_test (bitmap, values[i]), false,
				"Bit should not be set.");
	}
	r_bitmap_free (bitmap);
	mu_end;
}

bool test_r_bitmap_set_bytes(void) {
	const ut8 bytes[] = { 0xb2, 0x03, 0xff };
	RBitmap *bitmap = r_bitmap_new (10);
	r_bitmap_set_bytes (bitmap, bytes, sizeof (bytes));
	mu_assert_eq (r_bitmap_count (bitmap), 6, "Count should ignore tail bits.");
	mu_assert_eq (r_bitmap_test (bitmap, 0), false, "Bit should not be set.");
	mu_assert_eq (r_bitmap_test (bitmap, 1), true, "Bit should be set.");
	mu_assert_eq (r_bitmap_test (bitmap, 10), false, "Out of range bit should be false.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 0), 1, "Next set bit mismatch.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 2), 4, "Next set bit mismatch.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 5), 5, "Next set bit mismatch.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 6), 7, "Next set bit mismatch.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 8), 8, "Next set bit mismatch.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 9), 9, "Next set bit mismatch.");
	mu_assert_eq (r_bitmap_find_next_set (bitmap, 10), SZT_MAX, "No set bit expected.");
	r_bitmap_free (bitmap);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_bitmap_set);
	mu_run_test (test_r_bitmap_set_bytes);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
