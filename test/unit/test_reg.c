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

bool test_r_reg_get_value_gpr(void) {
	RReg *reg;
	ut64 value;

	reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg,
			"gpr eax .32 0 0\n\
			gpr	ax	.16	0	0\n\
			gpr	ah	.8	1	0\n\
			gpr	al	.8	0	0\n\
			gpr	ebx	.32	40	0\n\
			gpr	bx	.16	40	0\n\
			gpr	bh	.8	41	0\n\
			gpr	bl	.8	40	0");

	mu_assert_eq (r_reg_setv (reg, "eax", 0x01234567),
		true, "set eax register value to 0x01234567");

	value = r_reg_getv (reg, "eax");
	mu_assert_eq (value, 0x01234567, "get eax register value");

	value = r_reg_getv (reg, "ax");
	mu_assert_eq (value, 0x4567, "get ax register value");

	value = r_reg_getv (reg, "ah");
	mu_assert_eq (value, 0x45, "get ah register value");

	value = r_reg_getv (reg, "al");
	mu_assert_eq (value, 0x67, "get al register value");

	mu_assert_eq (r_reg_setv (reg, "ebx", 0x89ab0000),
		true, "set ebx register value to 0x89ab0000");

	value = r_reg_getv (reg, "ebx");
	mu_assert_eq (value, 0x89ab0000, "get ebx register value");

	mu_assert_eq (r_reg_setv (reg, "bh", 0xcd),
		true, "set bh register value to 0xcd");

	mu_assert_eq (r_reg_setv (reg, "bl", 0xef),
		true, "set bh register value to 0xef");

	value = r_reg_getv (reg, "bx");
	mu_assert_eq (value, 0xcdef, "get bx register value");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_get_value_flag(void) {
	RReg *reg;
	RRegItem *r;
	ut64 value;

	reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg,
			"gpr	eflags	.32	0		0	c1p.a.zstido.n.rv\n\
			gpr		flags	.16	0		0\n\
			gpr		cf		.1	.0	0	carry\n\
			gpr		pf		.1	.2	0	parity\n\
			gpr		af		.1	.4	0	adjust\n\
			gpr		zf		.1	.6	0	zero\n\
			gpr		sf		.1	.7	0	sign\n\
			gpr		tf		.1	.8	0	trap\n\
			gpr		if		.1	.9	0	interrupt\n\
			gpr		df		.1	.10	0	direction\n\
			gpr		of		.1	.11	0	overflow");

	r = r_reg_get (reg, "eflags", R_REG_TYPE_FLG);
	r_reg_set_value (reg, r, 0x00000346);

	value = r_reg_getv (reg, "cf");
	mu_assert_eq (value, 0, "get cf flag value");

	value = r_reg_getv (reg, "pf");
	mu_assert_eq (value, 1, "get pf flag value");

	value = r_reg_getv (reg, "af");
	mu_assert_eq (value, 0, "get af flag value");

	value = r_reg_getv (reg, "zf");
	mu_assert_eq (value, 1, "get zf flag value");

	value = r_reg_getv (reg, "sf");
	mu_assert_eq (value, 0, "get sf flag value");

	value = r_reg_getv (reg, "tf");
	mu_assert_eq (value, 1, "get tf flag value");

	value = r_reg_getv (reg, "df");
	mu_assert_eq (value, 0, "get df flag value");

	r_reg_free (reg);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_reg_set_name);
	mu_run_test (test_r_reg_set_profile_string);
	mu_run_test (test_r_reg_get_value_gpr);
	mu_run_test (test_r_reg_get_value_flag);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
