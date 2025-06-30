/* radare2 - LGPL - Copyright 2020 - pancake */

#include <r_util.h>
#include "minunit.h"

int test_overflow_add(void) {
	mu_assert_true (UT8_ADD_OVFCHK (250, 32), "ut8-add 1");
	mu_assert_false (UT8_ADD_OVFCHK (250, 2), "ut8-add 2");
	mu_assert_false (UT16_ADD_OVFCHK (ST16_MAX, 2), "ut16-add 2");
	mu_assert_true (ST16_ADD_OVFCHK (ST16_MAX, 2), "st16-add 2");
	mu_assert_true (ST16_ADD_OVFCHK (ST16_MAX - 2, 4), "st16-add 2");
	mu_assert_true (ST16_ADD_OVFCHK (1, ST16_MAX), "st16-add 3");

	mu_assert_true (ST16_ADD_OVFCHK (ST16_MIN, (st16)-1), "st16-add (min, -1)");
	mu_assert_true (UT16_ADD_OVFCHK (10, (ut16)-20), "ut16-add (10, -20)");
	mu_assert_false (ST16_ADD_OVFCHK ((st16)-10, 20), "st16-add (-10, 20)");
	mu_assert_true (ST32_ADD_OVFCHK (ST32_MIN, (st32)-20), "st32-add (min, -20)");
	mu_assert_false (ST32_ADD_OVFCHK ((st32)-10, 20), "st32-add (-10, 20)");
	mu_assert_true (ST64_ADD_OVFCHK (ST64_MIN, (st64)-20), "st64-add (min, -20)");
	mu_assert_false (ST64_ADD_OVFCHK ((st64)-10, 20), "st64-add 3");
	mu_end;
}

int test_underflow_sub(void) {
	mu_assert_false (ST16_SUB_OVFCHK (10, 210), "st16-sub-sign-underflow");
	mu_assert_true (UT16_SUB_OVFCHK (10, 210), "ut16-sub-underflow");
	mu_assert_true (ST16_SUB_OVFCHK (ST16_MIN, 210), "st16-sub-underflow");
	mu_end;
}

int test_underflow_add(void) {
	mu_assert_false (ST16_SUB_OVFCHK (10, (st16)-210), "st16-sub");
	mu_assert_false (ST16_SUB_OVFCHK (10, 10), "st16-sub 10");
	mu_assert_true (ST16_SUB_OVFCHK (ST16_MIN, 11), "st16-sub 10-11");
	mu_assert_false (ST16_SUB_OVFCHK (10, 11), "st16-sub 10-11");
	mu_assert_true (UT16_SUB_OVFCHK (10, 11), "ut16-sub 10-11");
	mu_end;
}

int test_overflow_mul(void) {
	mu_assert_true (UT8_MUL_OVFCHK (16, 32), "ut8-mul");
	mu_assert_false (UT8_MUL_OVFCHK (16, 2), "ut8-mul 2");
	mu_assert_true (ST8_MUL_OVFCHK (16, 100), "st8-mul 3");
	mu_assert_false (ST8_MUL_OVFCHK (16, 1), "st8-mul 4");
	mu_assert_false (ST8_MUL_OVFCHK (-2, 2), "st8-mul sign overflow");
	mu_assert_false (ST8_MUL_OVFCHK (-1, 1), "st8-mul sign overflow");
	mu_assert_false (ST8_MUL_OVFCHK (1, -1), "st8-mul sign overflow");
	mu_assert_false (ST8_MUL_OVFCHK (2, -2), "st8-mul sign overflow");
	mu_assert_false (ST8_MUL_OVFCHK (-1, -2), "st8-mul sign overflow");
	mu_assert_false (ST8_MUL_OVFCHK (-2, -1), "st8-mul sign overflow");
	mu_assert_true (ST8_MUL_OVFCHK (-16, 100), "st8-mul sign overflow");
	mu_assert_true (ST8_MUL_OVFCHK (100, -16), "st8-mul sign overflow");
	mu_assert_false (ST8_MUL_OVFCHK (3, -16), "st8-mul sign overflow");
	mu_end;
}

int test_overflow_mul2(void) {
	mu_assert_false (ST8_MUL_OVFCHK (-1, 0), "st8-mul2 -1 0");
	mu_assert_false (ST8_MUL_OVFCHK (1, 0), "st8-mul2 -1 0");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_overflow_add);
	mu_run_test (test_underflow_add);
	mu_run_test (test_underflow_sub);
	mu_run_test (test_overflow_mul);
	mu_run_test (test_overflow_mul2);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
