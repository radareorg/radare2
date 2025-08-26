#include <r_util.h>
#include "minunit.h"

static RNum *num;
static ut64 result;

static bool test_r_math_eq(void) {
	// 2 == 3 should yield false
    result = r_num_math(num, "2 == 3");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"Two should be not equal to three");

	// -5 == -5 should yield true
    result = r_num_math(num, "-5 == -5");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"Minus five should be equal to minus 5");
	mu_end;
}

static bool test_r_math_neq(void) {
	// 0x1a != 0x1a should yield false
    result = r_num_math(num, "0x1a != 0x1a");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"0x1a should be not different to 0x1a");

	// -2 != 2 should yield true
    result = r_num_math(num, "-2 != 2");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"Minus two should be different to two");
	mu_end;
}

bool test_r_math_bool_expr(void) {
    // NOT operator
    result = r_num_math(num, "!(0)");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"NOT 0 == 1");

    result = r_num_math(num, "!(1)");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"NOT 1 == 0");

    // AND operator
    result = r_num_math(num, "0 && 0");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"0 AND 0 == 0");

    result = r_num_math(num, "0 && 1");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"0 AND 1 == 0");

    result = r_num_math(num, "1 && 0");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"1 AND 0 == 0");

    result = r_num_math(num, "1 && 1");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"1 AND 1 == 1");

    // OR operator
    result = r_num_math(num, "0 || 0");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"0 OR 0 == 0");

    result = r_num_math(num, "0 || 1");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"0 OR 1 == 1");

    result = r_num_math(num, "1 || 0");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"1 OR 0 == 1");

    result = r_num_math(num, "1 || 1");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"1 OR 1 == 1");

    // XOR operator
    result = r_num_math(num, "0 ^^ 0");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"0 XOR 0 == 0");

    result = r_num_math(num, "0 ^^ 1");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"0 XOR 1 == 1");

    result = r_num_math(num, "1 ^^ 0");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"1 XOR 0 == 1");

    result = r_num_math(num, "1 ^^ 1");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"1 XOR 1 == 0");

    // combining boolean operators together
    result = r_num_math(num, "(1 && !(0)) || (1 && (1 || 0))");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"Should be true");

    result = r_num_math(num, "(0 ^^ 1) && (1 || !(0 && 1))");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"Should be true");

    result = r_num_math(num, "(0 ^^ 1) && (!(1 ^^ 0) || !(1 && 1))");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)0,
			"Should be false");

	mu_end;
}

bool test_r_math_act_on_subexprs(void) {
    result = r_num_math(num, "!(!(234987))");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"NOT (NOT (<any number != 0>)) == 1");

    result = r_num_math(num, "!(2+2 - 4)");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)1,
			"NOT (2 + 2 - 4) == 1");

    result = r_num_math(num, "(~(-5) + 1)");
	mu_assert_eq ((int)(intptr_t)result, (int)(intptr_t)5,
			"The two's complement of -5 should be 5");

    mu_end;
}

int all_tests(void) {
	mu_run_test(test_r_math_eq);
    mu_run_test(test_r_math_bool_expr);
    mu_run_test(test_r_math_act_on_subexprs);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
    num = r_num_new (NULL, NULL, NULL);
	return all_tests();
}
