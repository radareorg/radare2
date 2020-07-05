#include <r_util.h>
#include "minunit.h"

int test_overflow_add(void) {
	int a = 250;
	int b = 32;
	if (UT8_ADD_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "ut8-add 1");
	}
	b = 2;
	if (UT8_ADD_OVFCHK(a, b)) {
		mu_assert_eq(a, b, "ut8-add 2");
	} else {
		// ok
	}
	a = ST16_MAX;
	if (UT16_ADD_OVFCHK(a, b)) {
		mu_assert_eq(a, b, "ut16-add");
	} else {
		// ok
	}
	if (ST16_ADD_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "st16-add");
	}
	a = UT16_MAX;
	b = 1;
	if (UT16_ADD_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "ut16-add");
	}
	a = 1;
	b = UT16_MAX;
	if (UT16_ADD_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "ut16-add");
	}
	mu_end;
}

int test_underflow_sub(void) {
	int a, b;
	// underflows
	a = 10;
	b = 210;
	if (ST16_SUB_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "st16-sub-underflow");
	}
	mu_end;
}

int test_underflow_add(void) {
	int a, b;
	// underflows
	a = 10;
	b = -210;
	if (ST16_ADD_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "st16-add");
	}
	a = 10;
	b = -10;
	if (ST16_ADD_OVFCHK(a, b)) {
		mu_assert_eq(a, b, "st16-add");
	} else {
		// ok
	}
	a = 10;
	b = -11;
	if (ST16_ADD_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "st16-add");
	}
	mu_end;
}

int test_overflow_mul(void) {
	int a = 16;
	int b = 32;
	if (UT8_MUL_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "ut8-mul");
	}
	b = 2;
	if (UT8_MUL_OVFCHK (a, b)) {
		mu_assert_eq (a, b, "ut8-mul");
	} else {
		// ok
	}
	b = 100;
	if (ST8_MUL_OVFCHK(a, b)) {
		// ok
	} else {
		mu_assert_eq(a, b, "st8-mul");
	}
	b = 1;
	if (ST8_MUL_OVFCHK(a, b)) {
		mu_assert_eq(a, b, "st8-mul");
	} else {
		// ok
	}
	mu_end;
}

int all_tests() {
	mu_run_test(test_overflow_add);
	mu_run_test(test_underflow_add);
	mu_run_test(test_underflow_sub);
	mu_run_test(test_overflow_mul);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
