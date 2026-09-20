#include <r_anal.h>
#include "minunit.h"

bool test_x86_stack_access(void) {
	const struct {
		int bits;
		const char *hex;
		const char *pc;
		const char *sp;
		int width;
	} cases[] = {
		{ 16, "e80000", "ip", "sp", 2 },
		{ 16, "66e800000000", "ip", "sp", 4 },
		{ 16, "50", "ip", "sp", 2 },
		{ 16, "6650", "ip", "sp", 4 },
		{ 16, "9a00000000", "ip", "sp", 4 },
		{ 16, "669a000000000000", "ip", "sp", 8 },
		{ 32, "e800000000", "eip", "esp", 4 },
		{ 32, "66e80000", "eip", "esp", 2 },
		{ 64, "e800000000", "rip", "rsp", 8 },
	};
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "x86"), "select x86");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		mu_assert_true (r_anal_set_bits (anal, cases[i].bits), "set bits");
		ut8 buf[16];
		int len = r_hex_str2bin (cases[i].hex, buf);
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, 0x100, buf, len, R_ARCH_OP_MASK_VAL), len, "decode");
		RAnalValue *pc = r_list_get_n (op.access, 0);
		mu_assert_notnull (pc, "PC access");
		mu_assert_streq (pc->reg, cases[i].pc, "PC register matches mode");
		bool found = false;
		RListIter *iter;
		RAnalValue *value;
		r_list_foreach (op.access, iter, value) {
			if (value->type == R_ANAL_VAL_MEM && (value->access & R_PERM_W)) {
				mu_assert_streq (value->reg, cases[i].sp, "stack register matches mode");
				mu_assert_eq (value->memref, cases[i].width, "stack write width");
				mu_assert_eq (value->delta, -cases[i].width, "stack write displacement");
				found = true;
			}
		}
		mu_assert_true (found, "instruction writes the stack");
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_x86_stack_access);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
