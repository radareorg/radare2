#include <r_anal.h>
#include "minunit.h"

static int reg_access(RAnalOp *op, const char *name) {
	int access = 0;
	RListIter *iter;
	RAnalValue *value;
	r_list_foreach (op->access, iter, value) {
		if (value->type == R_ANAL_VAL_REG && !strcmp (value->reg, name)) {
			access |= value->access;
		}
	}
	return access;
}

static bool test_arm_predicate_access(void) {
	const char *flags[] = { "zf", "cf", "nf", "vf" };
	const int conditions[] = { 1, 1, 2, 2, 4, 4, 8, 8, 3, 3, 12, 12, 13, 13, 0 };
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "arm"), "select arm");
	mu_assert_true (r_anal_set_bits (anal, 32), "set bits");
	size_t condition, flag;
	for (condition = 0; condition < R_ARRAY_SIZE (conditions); condition++) {
		ut8 buf[] = { 1, 0, 0xa0, 1 | (condition << 4) };
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, 0, buf, sizeof (buf), R_ARCH_OP_MASK_VAL), 4, "decode conditional move");
		mu_assert_eq (reg_access (&op, "r0"), R_PERM_W, "possible destination write");
		mu_assert_eq (reg_access (&op, "r1"), R_PERM_R, "possible source read");
		for (flag = 0; flag < R_ARRAY_SIZE (flags); flag++) {
			mu_assert_eq (reg_access (&op, flags[flag]), (conditions[condition] & (1 << flag))? R_PERM_R: 0, "condition flag read");
		}
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_arm_register_access(void) {
	const struct {
		const char *hex;
		const char *reg;
		int access;
	} cases[] = {
		{ "1eff2f01", "lr", R_PERM_R }, // bxeq lr
		{ "1eff2f01", "pc", R_PERM_W },
		{ "33ff2f01", "r3", R_PERM_R }, // blxeq r3
		{ "33ff2f01", "lr", R_PERM_W },
		{ "33ff2f01", "pc", R_PERM_RW },
		{ "01008002", "r0", R_PERM_RW }, // addeq r0, r0, 1
		{ "11028000", "r2", R_PERM_R }, // addeq r0, r0, r1, lsl r2
		{ "0420b105", "r1", R_PERM_RW }, // ldreq r2, [r1, 4]!
		{ "0420b105", "r2", R_PERM_W },
		{ "0420a105", "r1", R_PERM_RW }, // streq r2, [r1, 4]!
		{ "0420a105", "r2", R_PERM_R },
		{ "10402d09", "sp", R_PERM_RW }, // pusheq {r4, lr}
		{ "10402d09", "lr", R_PERM_R },
		{ "01009002", "cpsr", R_PERM_W }, // addseq r0, r0, 1
	};
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "arm"), "select arm");
	mu_assert_true (r_anal_set_bits (anal, 32), "set bits");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		ut8 buf[4];
		int len = r_hex_str2bin (cases[i].hex, buf);
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, 0, buf, len, R_ARCH_OP_MASK_VAL), len, "decode");
		mu_assert_eq (reg_access (&op, cases[i].reg), cases[i].access, cases[i].hex);
		mu_assert_eq (reg_access (&op, "zf"), R_PERM_R, "predicate read");
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_arm_access_mask(void) {
	const int masks[] = { R_ARCH_OP_MASK_BASIC, R_ARCH_OP_MASK_ESIL, R_ARCH_OP_MASK_DISASM,
		R_ARCH_OP_MASK_VAL, R_ARCH_OP_MASK_OPEX };
	const ut8 buf[] = { 1, 0, 0xa0, 1 };
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "arm"), "select arm");
	mu_assert_true (r_anal_set_bits (anal, 32), "set bits");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (masks); i++) {
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, 0, buf, sizeof (buf), masks[i]), 4, "decode");
		mu_assert_eq (!!op.access, !!(masks[i] & (R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_OPEX)), "access collection is opt-in");
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_thumb_it_access(void) {
	const ut8 buf[] = { 0x8c, 0xbf, 0x08, 0x46, 0x10, 0x46 }; // ite hi; movhi r0, r1; movls r0, r2
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "arm"), "select arm");
	mu_assert_true (r_anal_set_bits (anal, 16), "set bits");
	int i;
	for (i = 0; i < sizeof (buf); i += 2) {
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, i, buf + i, sizeof (buf) - i, R_ARCH_OP_MASK_VAL), 2, "decode IT block");
		if (i) {
			mu_assert_eq (reg_access (&op, "r0"), R_PERM_W, "predicated write");
			mu_assert_eq (reg_access (&op, i == 2? "r1": "r2"), R_PERM_R, "predicated read");
			mu_assert_eq (reg_access (&op, "zf"), R_PERM_R, "IT zero flag");
			mu_assert_eq (reg_access (&op, "cf"), R_PERM_R, "IT carry flag");
		} else {
			mu_assert_eq (reg_access (&op, "zf"), 0, "IT itself does not test flags");
			mu_assert_eq (reg_access (&op, "cf"), 0, "IT itself does not test flags");
		}
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_arm_predicate_access);
	mu_run_test (test_arm_register_access);
	mu_run_test (test_arm_access_mask);
	mu_run_test (test_thumb_it_access);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
