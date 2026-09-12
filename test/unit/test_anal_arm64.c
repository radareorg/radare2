#include <r_core.h>
#include "minunit.h"

static void write_hex(RCore *core, ut64 addr, const char *hex) {
	size_t size = 0;
	ut8 *bytes = r_hex_str2bin_dup (hex, &size);
	r_io_write_at (core->io, addr, bytes, size);
	free (bytes);
}

static RCore *arm64_core(const char *hex) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "arm");
	r_config_set_i (core->config, "asm.bits", 64);
	r_config_set_b (core->config, "anal.nopskip", false);
	core->io->va = true;
	r_io_open_at (core->io, "malloc://1024", R_PERM_RWX, 0, 0);
	write_hex (core, 0x100, hex);
	return core;
}

static void analyze(RCore *core, ut64 addr) {
	r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, 256);
}

static bool test_arm64_br_registers(void) {
	int reg, jmptbl;
	for (jmptbl = 0; jmptbl < 2; jmptbl++) {
		for (reg = 0; reg < 31; reg++) {
			RCore *core = arm64_core ("1f2003d500001fd6000020d41f2003d5");
			ut8 br[4];
			r_write_le32 (br, 0xd61f0000 | (reg << 5));
			r_io_write_at (core->io, 0x104, br, sizeof (br));
			r_config_set_b (core->config, "anal.jmptbl", jmptbl);
			analyze (core, 0x100);
			RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x100);
			mu_assert_notnull (bb, "BR block");
			mu_assert_eq (bb->size, 8, "BR ends block before padding");
			mu_assert_eq (bb->ninstr, 2, "BR instruction count");
			mu_assert_eq (bb->jump, UT64_MAX, "no invented jump");
			mu_assert_eq (bb->fail, UT64_MAX, "no fallthrough");
			r_core_free (core);
		}
	}
	mu_end;
}

static bool test_arm64_computed_br(void) {
	// BatteryLife: adrp/add x5; mov x3, 0x28; sub x4, x5, x3; br x4.
	RCore *core = arm64_core ("05000090a5f00491030580d2a40003cb80001fd6e0008052c0035fd6");
	analyze (core, 0x100);
	RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x100);
	RAnalBlock *next = r_anal_get_block_at (core->anal, 0x114);
	mu_assert_notnull (bb, "computed BR block");
	mu_assert_eq (bb->size, 20, "terminate at BR");
	mu_assert_eq (bb->jump, 0x114, "resolved destination is BR + 4");
	mu_assert_eq (bb->fail, UT64_MAX, "destination is a jump, not fallthrough");
	mu_assert_notnull (next, "reachable continuation");
	mu_assert_eq (next->size, 8, "continuation includes RET");
	r_core_free (core);
	mu_end;
}

static bool test_arm64_br_provenance(void) {
	const struct {
		const char *hex;
		ut64 target;
	} variants[] = {
		{ "a400001080001fd6000020d4000020d4000020d4c0035fd6", 0x114 }, // ADR, skip padding
		{ "042080d28450009180001fd6000020d4000020d4c0035fd6", 0x114 }, // MOVZ / ADD
		{ "e4ff9fd2842280f280001fd6000020d4000020d4c0035fd6", 0x114 }, // MOVK keeps known bits
		{ "04008092840400918450049180001fd6000020d4c0035fd6", 0x114 }, // MOVN / wrapping ADD
		{ "a5000010e40305aa1f2003d580001fd6000020d4c0035fd6", 0x114 }, // MOV alias / NOP
		{ "a4000010e403002a80001fd6000020d4000020d4c0035fd6", UT64_MAX }, // W write kills X
		{ "a4000010040040f980001fd6000020d4000020d4c0035fd6", UT64_MAX }, // load kills value
		{ "a40000101f00009480001fd6000020d4000020d4c0035fd6", UT64_MAX }, // call barrier
		{ "0400001080001fd6000020d4", 0x100 }, // backwards / self-loop
		{ "242280d280001fd6000020d4", UT64_MAX }, // unaligned target 0x111
		{ "040082d280001fd6000020d4", UT64_MAX }, // unmapped target 0x1000
		{ "1f2003d5110a1fd7000020d4", UT64_MAX }, // authenticated BR is not plain BR
	};
	size_t i;
	int jmptbl;
	for (jmptbl = 0; jmptbl < 2; jmptbl++) {
		for (i = 0; i < R_ARRAY_SIZE (variants); i++) {
			RCore *core = arm64_core (variants[i].hex);
			write_hex (core, 0x180, "c0035fd6");
			r_config_set_b (core->config, "anal.jmptbl", jmptbl);
			analyze (core, 0x100);
			RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x100);
			mu_assert_notnull (bb, "constant provenance block");
			mu_assert_eq (bb->jump, variants[i].target, "only follow proven aligned local targets");
			mu_assert_eq (bb->fail, UT64_MAX, "BR never falls through");
			if (variants[i].target == 0x114) {
				mu_assert_notnull (r_anal_get_block_at (core->anal, 0x114), "non-adjacent RET is reachable");
			}
			r_core_free (core);
		}
	}
	RCore *core = arm64_core ("1f2003d500023fd600008052c0035fd6"); // NOP; BLR; MOV; RET
	analyze (core, 0x100);
	RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x100);
	mu_assert_notnull (bb, "BLR control");
	mu_assert_eq (bb->size, 16, "indirect calls still fall through");
	r_core_free (core);
	mu_end;
}

static bool test_arm64_switch_successors(void) {
	const struct {
		ut32 load;
		ut32 add;
		const char *table;
		int esize;
		ut64 base;
		ut64 case1;
	} variants[] = {
		{ 0xb8a0792b, 0x8b0b014a, "0000000008000000", 4, 0x11c, 0x124 }, // ldrsw; add
		{ 0x7860792b, 0x8b0b094a, "00000200", 2, 0x11c, 0x124 }, // ldrh; add lsl 2
		{ 0x3860692b, 0x8b0b094a, "0002", 1, 0x11c, 0x124 }, // ldrb; add lsl 2
		{ 0x7860792b, 0x8b0b054a, "00000400", 2, 0x11c, 0x124 }, // ldrh; add lsl 1
		{ 0x7860792b, 0x8b0b014a, "00000800", 2, 0x11c, 0x124 }, // ldrh; unscaled add
		{ 0x3860692b, 0x8b0b014a, "0008", 1, 0x11c, 0x124 }, // ldrb; unscaled add
		{ 0xb8a0792b, 0x8b0b014a, "f8ffffff00000000", 4, 0x124, 0x124 }, // negative signed word
		{ 0x78a0792b, 0x8b0b014a, "f8ff0000", 2, 0x124, 0x124 }, // negative signed halfword
		{ 0x38a0692b, 0x8b0b014a, "f800", 1, 0x124, 0x124 }, // negative signed byte
		{ 0x3860692b, 0x8b0b094a, "0080", 1, 0x11c, 0x31c }, // high bit is unsigned
		{ 0xb8a0792b, 0x8b0b014a, "0000000000000000", 4, 0x11c, 0x11c }, // shared destination
		{ 0x7860792b, 0x8b2ba94a, "00000200", 2, 0x11c, 0x124 }, // ADD SXTH #2
		{ 0x7860792b, 0x8b2ba94a, "feff0000", 2, 0x124, 0x124 }, // extension, not load, is signed
		{ 0x3860692b, 0x8b2b094a, "0080", 1, 0x11c, 0x31c }, // ADD UXTB #2
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (variants); i++) {
		// cmp w0, 1; b.hi default; adr table; adr case0; load; add; br x10.
		RCore *core = arm64_core ("1f04007168010054490200108a0000102b79a0b84a010b8b40011fd6e0008052c0035fd620018052c0035fd6");
		ut8 dispatch[8];
		r_write_le32 (dispatch, variants[i].load);
		r_write_le32 (dispatch + 4, variants[i].add);
		r_io_write_at (core->io, 0x110, dispatch, sizeof (dispatch));
		r_write_le32 (dispatch, 0x1000000a | ((variants[i].base - 0x10c) << 3));
		r_io_write_at (core->io, 0x10c, dispatch, 4);
		write_hex (core, 0x150, variants[i].table);
		write_hex (core, 0x130, "c0035fd6");
		write_hex (core, 0x31c, "20018052c0035fd6");
		analyze (core, 0x100);
		RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x108);
		mu_assert_notnull (bb, "dispatcher block");
		mu_assert_eq (bb->size, 20, "switch BR ends its own block");
		mu_assert_eq (bb->jump, UT64_MAX, "no fake case0 fallthrough");
		mu_assert_eq (bb->fail, UT64_MAX, "no switch fallthrough");
		mu_assert_notnull (bb->switch_op, "resolved switch");
		mu_assert_eq (r_list_length (bb->switch_op->cases), 2, "include inclusive upper-bound case");
		mu_assert_eq (bb->switch_op->addr, 0x118, "switch is attached to BR");
		mu_assert_eq (bb->switch_op->amount, 2, "complete bounded table");
		mu_assert_eq (bb->switch_op->dsize, variants[i].esize, "table element size");
		mu_assert_notnull (r_meta_get_at (core->anal, 0x150, R_META_TYPE_DATA, NULL), "table is data, not another function");
		RAnalCaseOp *case0 = r_list_get_n (bb->switch_op->cases, 0);
		RAnalCaseOp *case1 = r_list_get_n (bb->switch_op->cases, 1);
		mu_assert_eq (case0->jump, 0x11c, "zero delta case0 is BR + 4");
		mu_assert_eq (case1->jump, variants[i].case1, "scale and signedness match instructions");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x100);
		mu_assert_true (r_anal_function_contains (fcn, 0x11c), "case0 belongs to function");
		mu_assert_true (r_anal_function_contains (fcn, 0x120), "case0 RET is reachable");
		mu_assert_true (r_anal_function_contains (fcn, variants[i].case1 + 4), "case1 RET is reachable");
		r_core_free (core);
	}
	mu_end;
}

static bool test_arm64_unknown_exit_noreturn(void) {
	// cbz x0, unknown; bl known_noreturn; brk; nop; unknown: br x4.
	RCore *core = arm64_core ("800000b41f000094000020d41f2003d580001fd6000020d4");
	write_hex (core, 0x180, "c0035fd6");
	write_hex (core, 0x200, "c0ffff97c0035fd6");
	analyze (core, 0x100);
	analyze (core, 0x200);
	r_anal_noreturn_add (core->anal, NULL, 0x180);
	r_core_anal_propagate_noreturn (core, UT64_MAX);
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x100);
	RAnalBlock *caller = r_anal_get_block_at (core->anal, 0x200);
	mu_assert_notnull (fcn, "function with unknown exit");
	mu_assert_false (fcn->is_noreturn, "unknown indirect exit is not proof of noreturn");
	mu_assert_notnull (caller, "caller");
	mu_assert_eq (caller->size, 8, "keep caller continuation");
	RAnalBlock *chopped = r_anal_get_block_at (core->anal, 0x104);
	mu_assert_notnull (chopped, "known noreturn call block");
	mu_assert_eq (chopped->size, 4, "known noreturn still chops");
	mu_assert_eq (chopped->ninstr, 1, "chopping updates instruction count");
	mu_assert_eq (r_anal_bb_opaddr_i (chopped, 1), UT64_MAX, "removed RET has no instruction offset");
	r_core_free (core);
	mu_end;
}

static bool test_arm64_switch_producers(void) {
	// ired: copy the table/base register before overwriting its source.
	RCore *core = arm64_core ("1f0400716801005448020010ea0308aa4879a0b808010a8b00011fd6e0008052c0035fd620018052c0035fd6");
	write_hex (core, 0x150, "ccffffffd4ffffff");
	write_hex (core, 0x130, "c0035fd6");
	analyze (core, 0x100);
	RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x108);
	mu_assert_notnull (bb->switch_op, "MOV alias preserves the table base");
	mu_assert_eq (r_list_length (bb->switch_op->cases), 2, "aliased table cases");
	RAnalCaseOp *kase = r_list_first (bb->switch_op->cases);
	mu_assert_eq (kase->jump, 0x11c, "aliased case0 after BR");
	r_core_free (core);
	// Alamofire: the LDP after ADD is not the table load.
	core = arm64_core ("1f0400716801005449020010aa0000102b79a0b84a010b8bb85f78a940011fd6e0008052c0035fd620018052c0035fd6");
	write_hex (core, 0x150, "0000000008000000");
	write_hex (core, 0x130, "c0035fd6");
	analyze (core, 0x100);
	bb = r_anal_get_block_at (core->anal, 0x108);
	mu_assert_notnull (bb->switch_op, "later load does not hide the switch");
	mu_assert_eq (bb->size, 24, "BR still terminates after LDP");
	mu_assert_eq (bb->switch_op->dsize, 4, "matched table load determines element width");
	kase = r_list_first (bb->switch_op->cases);
	mu_assert_eq (kase->jump, 0x120, "case0 after LDP and BR");
	r_core_free (core);
	mu_end;
}

static bool test_arm64_switch_noreturn(void) {
	int complete;
	for (complete = 0; complete < 2; complete++) {
		RCore *core = arm64_core ("1f04007168010054490200108a0000102b79a0b84a010b8b40011fd6");
		write_hex (core, 0x11c, "19000094000020d4");
		write_hex (core, 0x124, "17000094000020d4");
		write_hex (core, 0x130, "14000094000020d4");
		write_hex (core, 0x150, complete? "0000000008000000": "0000000001000000");
		write_hex (core, 0x180, "c0035fd6");
		write_hex (core, 0x200, "c0ffff97c0035fd6");
		analyze (core, 0x100);
		analyze (core, 0x200);
		analyze (core, 0x180);
		RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x108);
		mu_assert_notnull (bb->switch_op, "partial switch is retained");
		mu_assert_eq (bb->switch_op->amount, 2, "expected case count is not reduced to valid count");
		mu_assert_eq (r_list_length (bb->switch_op->cases), complete? 2: 1, "unaligned case rejected");
		r_anal_noreturn_add (core->anal, NULL, 0x180);
		r_core_anal_propagate_noreturn (core, UT64_MAX);
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x100);
		mu_assert_eq (fcn->is_noreturn, complete, "only a complete noreturn switch propagates");
		RAnalBlock *caller = r_anal_get_block_at (core->anal, 0x200);
		mu_assert_eq (caller->size, complete? 4: 8, "partial switch preserves caller return");
		r_core_free (core);
	}
	mu_end;
}

static bool test_arm64_switch_spilled_base(void) {
	// Save the table address, reuse its register, then reload it at dispatch.
	RCore *core = arm64_core ("89020010e90b00f9e90300aa1f04007188010054e90b40f98a0000102b79a0b84a010b8b40011fd6e0008052c0035fd620018052c0035fd6");
	write_hex (core, 0x150, "0000000008000000");
	write_hex (core, 0x140, "c0035fd6");
	analyze (core, 0x100);
	RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x114);
	mu_assert_notnull (bb, "reload dispatcher");
	mu_assert_notnull (bb->switch_op, "spilled table base");
	mu_assert_eq (bb->switch_op->daddr, 0x150, "use the saved address, not the reused register");
	mu_assert_eq (r_list_length (bb->switch_op->cases), 2, "reload switch cases");
	RAnalCaseOp *kase = r_list_first (bb->switch_op->cases);
	mu_assert_eq (kase->jump, 0x128, "case0 after the reload dispatcher BR");
	r_core_free (core);
	mu_end;
}

static bool test_arm64_switch_selected_index(void) {
	// Select x8 from {0, 1, 2, 4}; the nearby CMP concerns w2, not x8.
	RCore *core = arm64_core ("890080524a0080524931891a5f00047128259f1a5f000071e803881a21020034090300108a0000102b6968384a090b8b40011fd600008052c0035fd620008052c0035fd640008052c0035fd660008052c0035fd680008052c0035fd6");
	write_hex (core, 0x180, "0002040608");
	write_hex (core, 0x160, "c0035fd6");
	analyze (core, 0x100);
	RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x120);
	mu_assert_notnull (bb, "selected-index dispatcher");
	mu_assert_notnull (bb->switch_op, "selected-index switch");
	mu_assert_eq (bb->switch_op->amount, 5, "index range, not unrelated compare, bounds table");
	mu_assert_eq (r_list_length (bb->switch_op->cases), 5, "selected-index cases");
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x100);
	mu_assert_true (r_anal_function_contains (fcn, 0x138), "case0 RET after BR");
	mu_assert_true (r_anal_function_contains (fcn, 0x158), "highest selected case RET");
	r_core_free (core);
	mu_end;
}

static bool test_arm64_switch_exclusive_bound(void) {
	int cond;
	for (cond = 0; cond <= 2; cond += 2) { // B.EQ and B.HS exclude the upper bound
		RCore *core = arm64_core ("1f08007160010054490200108a0000102b79a0b84a010b8b40011fd6e0008052c0035fd620018052c0035fd6");
		ut8 branch[4];
		r_write_le32 (branch, 0x54000160 | cond);
		r_io_write_at (core->io, 0x104, branch, sizeof (branch));
		write_hex (core, 0x150, "000000000800000010000000");
		write_hex (core, 0x130, "c0035fd6");
		analyze (core, 0x100);
		RAnalBlock *bb = r_anal_get_block_at (core->anal, 0x108);
		mu_assert_notnull (bb->switch_op, "exclusive-bound switch");
		mu_assert_eq (r_list_length (bb->switch_op->cases), 2, "do not read a third entry past the bound");
		r_core_free (core);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_arm64_br_registers);
	mu_run_test (test_arm64_computed_br);
	mu_run_test (test_arm64_br_provenance);
	mu_run_test (test_arm64_switch_successors);
	mu_run_test (test_arm64_unknown_exit_noreturn);
	mu_run_test (test_arm64_switch_producers);
	mu_run_test (test_arm64_switch_noreturn);
	mu_run_test (test_arm64_switch_spilled_base);
	mu_run_test (test_arm64_switch_selected_index);
	mu_run_test (test_arm64_switch_exclusive_bound);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
