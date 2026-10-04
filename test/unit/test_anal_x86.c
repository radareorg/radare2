#include <r_anal.h>
#include <r_core.h>
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
		{ 32, "9a000000000000", "eip", "esp", 8 },
		{ 32, "669a00000000", "eip", "esp", 4 },
		{ 32, "50", "eip", "esp", 4 },
		{ 32, "6650", "eip", "esp", 2 },
		{ 64, "e800000000", "rip", "rsp", 8 },
		{ 64, "66e800000000", "rip", "rsp", 8 },
		{ 64, "50", "rip", "rsp", 8 },
		{ 64, "6650", "rip", "rsp", 2 },
		{ 16, "b80000", "ip", "sp", 0 },
		{ 32, "b800000000", "eip", "esp", 0 },
		{ 64, "4889c3", "rip", "rsp", 0 },
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
		mu_assert_eq (found, cases[i].width != 0, "only stack-writing instructions store through SP");
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

bool test_x86_cs_frame_pointer(void) {
	const struct {
		const char *name;
		const char *hex[3];
		bool bp_frame;
	} cases[] = {
		{ "mov bp, sp", { "89e5", "89e5", "4889e5" }, true },
		{ "mov bp, ax", { "89c5", "89c5", "4889c5" }, false },
		{ "lea bp, [other]", { "8d2f", "8d28", "488d28" }, false },
		{ "add bp, 1", { "83c501", "83c501", "4883c501" }, false },
		{ "sub bp, 1", { "83ed01", "83ed01", "4883ed01" }, false },
		{ "and bp, -16", { "83e5f0", "83e5f0", "4883e5f0" }, false },
		{ "or bp, 1", { "83cd01", "83cd01", "4883cd01" }, false },
		{ "xor bp, ax", { "31c5", "31c5", "4831c5" }, false },
		{ "not bp", { "f7d5", "f7d5", "48f7d5" }, false },
		{ "shl bp, 1", { "d1e5", "d1e5", "48d1e5" }, false },
		{ "shr bp, 1", { "d1ed", "d1ed", "48d1ed" }, false },
		{ "sar bp, 1", { "d1fd", "d1fd", "48d1fd" }, false },
		{ "rol bp, 1", { "d1c5", "d1c5", "48d1c5" }, false },
		{ "ror bp, 1", { "d1cd", "d1cd", "48d1cd" }, false },
		{ "cmovz bp, ax", { "0f44e8", "0f44e8", "480f44e8" }, false },
		{ "mov ax, bp", { "89e8", "89e8", "4889e8" }, true },
		{ "cmovz ax, bp", { "0f44c5", "0f44c5", "480f44c5" }, true },
		{ "cmp bp, ax", { "39c5", "39c5", "4839c5" }, true },
		{ "push bp", { "55", "55", "55" }, true },
		{ "pop bp", { "5d", "5d", "5d" }, true },
		{ "mov [bp-8], ax", { "8946f8", "8945f8", "488945f8" }, true },
		{ "mov ax, [bp-8]", { "8b46f8", "8b45f8", "488b45f8" }, true },
		{ "lea ax, [bp-8]", { "8d46f8", "8d45f8", "488d45f8" }, true },
		{ "add [bp-8], 1", { "8346f801", "8345f801", "488345f801" }, true },
		{ "not [bp-8]", { "f756f8", "f755f8", "48f755f8" }, true },
		{ "shl [bp-8], 1", { "d166f8", "d165f8", "48d165f8" }, true },
	};
	const int bits[] = { 16, 32, 64 };
	RCore *core = r_core_new ();
	RAnal *anal = core->anal;
	mu_assert_true (r_anal_use (anal, "x86"), "select Capstone x86");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://16", R_PERM_RWX, 0, 0), "open instruction buffer");
	RAnalFunction *fcn = r_anal_create_function (anal, "frame", 0, 0, NULL);
	mu_assert_notnull (fcn, "create function");
	RAnalBlock *bb = r_anal_create_block (anal, 0, 16);
	mu_assert_notnull (bb, "create block");
	r_anal_function_add_block (fcn, bb);
	r_unref (bb);
	size_t mode, i;
	for (mode = 0; mode < R_ARRAY_SIZE (bits); mode++) {
		mu_assert_true (r_anal_set_bits (anal, bits[mode]), "set bits");
		for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
			ut8 buf[16];
			int len = r_hex_str2bin (cases[i].hex[mode], buf);
			mu_assert_true (r_io_write_at (core->io, 0, buf, len), "write instruction");
			r_anal_block_set_size (bb, len);
			fcn->bp_frame = true;
			r_anal_function_check_bp_use (fcn);
			char message[128];
			snprintf (message, sizeof (message), "%d-bit %s", bits[mode], cases[i].name);
			mu_assert_eq (fcn->bp_frame, cases[i].bp_frame, message);
		}
	}
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_x86_stack_access);
	mu_run_test (test_x86_cs_frame_pointer);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
