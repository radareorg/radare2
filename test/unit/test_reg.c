#include <r_reg.h>
#include "minunit.h"

bool test_r_reg_set_name(void) {
	RReg *reg;

	reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_name (reg, R_REG_NAME_PC, "eip");
	const char *name = r_reg_get_name (reg, R_REG_NAME_PC);
	mu_assert_streq (name, "eip", "PC register alias is eip");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_set_profile_string(void) {
	RReg *reg;

	reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg, "=PC eip");
	const char *name = r_reg_get_name (reg, R_REG_NAME_PC);
	mu_assert_streq (name, "eip", "PC register alias is eip");

	mu_assert_eq (r_reg_set_profile_string (reg, "gpr eax .32 24 0"),
		true, "define eax register");

	mu_assert_eq (r_reg_setv (reg, "eax", 1234),
		true, "set eax register value to 1234");

	ut64 value = r_reg_getv (reg, "eax");
	mu_assert_eq (value, 1234, "get eax register value");

	r_reg_free (reg);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_reg_set_name);
	mu_run_test (test_r_reg_set_profile_string);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
