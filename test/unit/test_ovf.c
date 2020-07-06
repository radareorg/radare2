#include <r_util.h>
#include "minunit.h"

int test_overflow_add(void) {
	mu_assert_true (UT8_ADD_OVFCHK (250, 32), "ut8-add 1");
	mu_assert_false (UT8_ADD_OVFCHK (250, 2), "ut8-add 2");
	mu_assert_false (UT16_ADD_OVFCHK (ST16_MAX, 2), "ut16-add 2");
	mu_assert_true (ST16_ADD_OVFCHK (ST16_MAX, 2), "st16-add 2");
	mu_assert_true (ST16_ADD_OVFCHK (UT16_MAX, 1), "st16-add 2");
	mu_assert_true (ST16_ADD_OVFCHK (1, ST16_MAX), "st16-add 3");
	mu_end;
}

int test_underflow_sub(void) {
	mu_assert_true (ST16_SUB_OVFCHK (10, 210), "st16-sub-underflow");
	mu_end;
}

int test_underflow_add(void) {
	mu_assert_false (ST16_SUB_OVFCHK (10, -210), "st16-add");
	mu_assert_false (ST16_SUB_OVFCHK (10, 10), "st16-add 10");
	mu_assert_true (ST16_SUB_OVFCHK (10, 11), "st16-add 10-11");
	mu_end;
}

int test_overflow_mul(void) {
	mu_assert_true (UT8_MUL_OVFCHK (16, 32), "ut8-mul");
	mu_assert_false (UT8_MUL_OVFCHK (16, 2), "ut8-mul 2");
	mu_assert_true (ST8_MUL_OVFCHK (16, 100), "st8-mul 3");
	mu_assert_false (ST8_MUL_OVFCHK (16, 1), "st8-mul 4");
	mu_end;
}

int all_tests() {
	mu_run_test (test_overflow_add);
	mu_run_test (test_underflow_add);
	mu_run_test (test_underflow_sub);
	mu_run_test (test_overflow_mul);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
