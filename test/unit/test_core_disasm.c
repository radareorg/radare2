#include <r_core.h>
#include "minunit.h"

typedef struct {
	bool decoded;
	int size;
	int minsize;
	int maxsize;
	int step;
	int available;
	const char *mnemonic;
} VisualDecodeFixture;

static bool visual_test_decode(RArchSession *session, RAnalOp *op, RArchDecodeMask mask) {
	VisualDecodeFixture *fixture = session->data;
	fixture->available = op->size;
	op->size = fixture->size;
	r_anal_op_set_mnemonic (op, op->addr, fixture->mnemonic? fixture->mnemonic: "invalid");
	return fixture->decoded;
}

static int visual_test_info(RArchSession *session, ut32 query) {
	VisualDecodeFixture *fixture = session->data;
	switch (query) {
	case R_ARCH_INFO_MINOP_SIZE:
		return fixture->minsize;
	case R_ARCH_INFO_MAXOP_SIZE:
		return fixture->maxsize;
	}
	return 1;
}

static RArchPlugin visual_test_plugin = {
	.meta = { .name = "visual-test" },
	.arch = "x86",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.decode = visual_test_decode,
	.info = visual_test_info,
};

bool test_visual_disasm_invalid_sizes(void) {
	VisualDecodeFixture fixtures[] = {
		{ false, 2, 2, 4, 2, 0 },
		{ true, 0, 2, 4, 2, 0 },
		{ true, -1, 2, 4, 2, 0 },
		{ true, 1, 2, 4, 2, 0 },
		{ true, 4, 2, 4, 4, 0 },
		{ true, INT_MAX, 2, INT_MAX, 2, 0 },
		{ false, 0, 0, 0, 2, 0 },
		{ false, -1, -1, -1, 2, 0 },
	};
	RCore *core = r_core_new ();
	r_core_cmd0 (core, "o malloc://256; e arch.codealign=2");
	mu_assert_true (r_arch_plugin_add (core->anal->arch, &visual_test_plugin), "register test decoder");
	mu_assert_true (r_arch_use (core->anal->arch, core->anal->config, "visual-test"), "select test decoder");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (fixtures); i++) {
		core->anal->arch->session->data = &fixtures[i];
		RAnalOp op;
		int cols = 0;
		r_core_visual_disasm_down (core, &op, &cols);
		mu_assert_eq (cols, fixtures[i].step, "visual scroll advances to an aligned instruction");
		mu_assert_true (fixtures[i].available <= R_MAX (32, core->blocksize), "decoder buffer is bounded even with invalid archinfo");
		mu_assert_true (op.size > 0, "disassembler always supplies a positive instruction size");
		r_anal_op_fini (&op);
		core->visual.printidx = 1;
		core->print->cur_enabled = true;
		core->print->cur = 0;
		r_core_visual_cmd (core, "j");
		mu_assert_eq (core->print->cur, fixtures[i].step, "disassembly cursor also advances");
	}
	r_core_free (core);
	mu_end;
}

bool test_visual_disasm_unmapped(void) {
	RCore *core = r_core_new ();
	r_config_set_i (core->config, "arch.codealign", 4);
	RAnalOp op;
	int cols = 0;
	r_core_visual_disasm_down (core, &op, &cols);
	mu_assert_eq (cols, 4, "failed reads still allow aligned scrolling");
	r_anal_op_fini (&op);
	r_core_free (core);
	mu_end;
}

bool test_disasm_without_decoder(void) {
	RAsm *assembler = r_asm_new ();
	const ut8 bytes[] = { 0xff };
	RAnalOp op;
	int size = r_asm_disassemble (assembler, &op, bytes, sizeof (bytes));
	mu_assert_eq (size, 0, "missing decoder reports failure");
	mu_assert_eq (op.size, 1, "failed disassembly still allows forward progress");
	r_anal_op_fini (&op);
	r_asm_free (assembler);
	mu_end;
}

bool test_disasm_truncated_byte_selection(void) {
	RCore *core = r_core_new ();
	r_core_cmd0 (core, "e asm.arch=x86; e asm.bits=64; e asm.nbytes=3; e asm.flags=false; e asm.lines=false");
	r_core_cmd0 (core, "o malloc://32; wx 498bbc246801000090");
	int color, spacing, align, reverse;
	for (color = 0; color <= 2; color++) {
		r_config_set_i (core->config, "scr.color", color);
		r_config_set (core->config, "asm.highlight", color == 2? "0": "");
		const char *reset_code = color == 2? Color_RESET_NOBG: Color_RESET;
		for (spacing = 0; spacing <= 1; spacing++) {
			r_config_set_b (core->config, "asm.bytes.space", spacing);
			for (align = 0; align <= 1; align++) {
				r_config_set_b (core->config, "asm.bytes.align", align);
				for (reverse = 0; reverse <= 1; reverse++) {
					r_print_set_cursor (core->print, true, reverse? 0: 8, reverse? 8: 0);
					char *output = r_core_cmd_str (core, "pd 2");
					mu_assert_notnull (output, "disassembly output");
					mu_assert_notnull (strstr (output, Color_INVERT), "byte selection is highlighted");
					char *ellipsis = strstr (output, "..");
					mu_assert_notnull (ellipsis, "instruction bytes are truncated");
					char *reset = strstr (ellipsis, reset_code);
					char *opcode = strstr (ellipsis, "mov");
					mu_assert_notnull (opcode, "instruction mnemonic");
					mu_assert_true (reset && reset < opcode, "selection ends before instruction mnemonic");
					mu_assert_true (reset == ellipsis + 2, "selection ends before byte column padding");
					free (output);
				}
			}
		}
	}
	r_core_free (core);
	mu_end;
}

bool test_disasm_flag_byte_colors(void) {
	RCore *core = r_core_new ();
	r_core_cmd0 (core, "e asm.arch=x86; e asm.bits=64; e asm.flags=false; e asm.lines=false; e scr.color=1");
	r_core_cmd0 (core, "o malloc://32 0x1000; s 0x1000; wx 904889e590c3; f PATCH 3 @ 0x1001; fc red @ PATCH");
	r_core_cmd0 (core, "ec other yellow; ec btext cyan");
	int opcolor, spacing;
	for (opcolor = 0; opcolor <= 1; opcolor++) {
		r_config_set_b (core->config, "asm.bytes.opcolor", opcolor);
		for (spacing = 0; spacing <= 1; spacing++) {
			r_config_set_b (core->config, "asm.bytes.space", spacing);
			char *output = r_core_cmd_str (core, "pd 4");
			mu_assert_notnull (output, "disassembly output");
			mu_assert_notnull (strstr (output, Color_RED "48"), "flag color at first byte");
			mu_assert_notnull (strstr (output, Color_RED "89"), "flag color inside instruction");
			mu_assert_notnull (strstr (output, Color_RED "e5"), "flag color at last byte");
			mu_assert_null (strstr (output, Color_RED "90"), "bytes outside flag keep their normal color");
			free (output);
		}
	}
	r_core_cmd0 (core, "f PATCH 1 @ 0x1002; fc red @ PATCH");
	char *output = r_core_cmd_str (core, "pd 4");
	mu_assert_notnull (strstr (output, Color_RED "89"), "flag starts inside an instruction");
	mu_assert_null (strstr (output, Color_RED "48"), "byte before partial flag");
	mu_assert_null (strstr (output, Color_RED "e5"), "byte after partial flag");
	free (output);
	r_config_set_i (core->config, "scr.color", 0);
	output = r_core_cmd_str (core, "pd 4");
	mu_assert_null (strchr (output, '\x1b'), "disabled colors omit flag colors");
	free (output);
	r_config_set_i (core->config, "scr.color", 1);
	r_config_set_b (core->config, "asm.bytes", false);
	output = r_core_cmd_str (core, "pd 4");
	mu_assert_notnull (strstr (output, Color_RED "0x00001001"), "address marks a flag inside an instruction with hidden bytes");
	mu_assert_null (strstr (output, Color_RED "mov"), "flag colors do not affect the opcode");
	free (output);
	r_core_cmd0 (core, "f PATCH 4 @ 0x1001; fc red @ PATCH");
	output = r_core_cmd_str (core, "pd 4");
	mu_assert_notnull (strstr (output, Color_RED "0x00001001"), "first instruction in flag range");
	mu_assert_notnull (strstr (output, Color_RED "0x00001004"), "following instruction in flag range");
	mu_assert_null (strstr (output, Color_RED "0x00001000"), "address before flag range");
	mu_assert_null (strstr (output, Color_RED "0x00001005"), "address after flag range");
	free (output);
	r_core_cmd0 (core, "f TAIL 1 @ 0x1005; fc blue @ TAIL; e asm.bytes=true");
	output = r_core_cmd_str (core, "pd 4");
	mu_assert_notnull (strstr (output, Color_BLUE "c3"), "adjacent flag changes byte color");
	mu_assert_notnull (strstr (output, Color_BLUE "0x00001005"), "adjacent flag changes address color");
	free (output);
	r_core_cmd0 (core, "e asm.highlight=0x1001; e asm.nbytes=1");
	output = r_core_cmd_str (core, "pd 4");
	mu_assert_notnull (strstr (output, Color_RED "0x00001001 " Color_RESET_NOBG), "flag address color preserves line background");
	mu_assert_notnull (strstr (output, ".." Color_RESET_NOBG), "truncated flag bytes preserve line background");
	free (output);
	r_config_set_b (core->config, "scr.color.bytes", false);
	output = r_core_cmd_str (core, "pd 4");
	mu_assert_null (strstr (output, Color_BLUE "c3"), "disabled byte colors omit flag colors");
	mu_assert_notnull (strstr (output, Color_BLUE "0x00001005"), "address color is independent of byte colors");
	free (output);
	r_core_free (core);
	mu_end;
}

bool test_decode_invalid_mnemonic(void) {
	const struct {
		int bits;
		int len;
		bool bigendian;
		int mask;
		const char *text;
	} cases[] = {
		{ 8, 1, false, R_ARCH_OP_MASK_DISASM, ".byte 0x01" },
		{ 16, 2, false, R_ARCH_OP_MASK_DISASM, ".word 0x0201" },
		{ 32, 4, false, R_ARCH_OP_MASK_DISASM, ".dword 0x04030201" },
		{ 64, 8, false, R_ARCH_OP_MASK_DISASM, ".qword 0x0807060504030201" },
		{ 16, 2, true, R_ARCH_OP_MASK_DISASM, ".word 0x0102" },
		{ 32, 4, true, R_ARCH_OP_MASK_DISASM, ".dword 0x01020304" },
		{ 64, 8, true, R_ARCH_OP_MASK_DISASM, ".qword 0x0102030405060708" },
		{ 16, 1, false, R_ARCH_OP_MASK_DISASM, "invalid" },
		{ 32, 3, false, R_ARCH_OP_MASK_DISASM, "invalid" },
		{ 64, 7, false, R_ARCH_OP_MASK_DISASM, "invalid" },
		{ 64, 8, false, R_ARCH_OP_MASK_ESIL, "invalid" },
	};
	const ut8 bytes[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	VisualDecodeFixture fixture = { .size = 1 };
	RArchConfig config = { .invhex = true };
	RArchSession session = { .config = &config, .plugin = &visual_test_plugin, .data = &fixture };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		config.bits = cases[i].bits;
		config.endian = cases[i].bigendian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
		RAnalOp op = {0};
		r_anal_op_set_bytes (&op, 0, bytes, cases[i].len);
		mu_assert_false (r_arch_session_decode (&session, &op, cases[i].mask), "invalid instruction remains a decode failure");
		mu_assert_streq (op.mnemonic, cases[i].text, "shared disassembly fallback");
		r_anal_op_fini (&op);
	}
	fixture.mnemonic = "truncated from 8 to 4";
	config.bits = 32;
	for (i = 0; i < 2; i++) {
		config.invhex = i;
		RAnalOp op = {0};
		r_anal_op_set_bytes (&op, 0, bytes, 4);
		mu_assert_false (r_arch_session_decode (&session, &op, R_ARCH_OP_MASK_DISASM), "diagnostic still reports decode failure");
		mu_assert_streq (op.mnemonic, fixture.mnemonic, "preserve decoder diagnostic");
		r_anal_op_fini (&op);
	}
	mu_end;
}

static int ao_decode_count;
static RArchDecodeMask ao_decode_mask;

static bool ao_test_decode(RArchSession *session, RAnalOp *op, RArchDecodeMask mask) {
	ao_decode_count++;
	ao_decode_mask = mask;
	op->size = 1;
	op->type = R_ANAL_OP_TYPE_NOP;
	r_anal_op_set_mnemonic (op, op->addr, "nop");
	return true;
}

static RArchPlugin ao_test_plugin = {
	.meta = { .name = "ao-test" },
	.arch = "x86",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.decode = ao_test_decode,
};

bool test_ao_single_decode(void) {
	const char *commands[] = { "ao 3", "aoj 3", "aoe 3", "aoeq 3", "aos 3" };
	RCore *core = r_core_new ();
	r_core_cmd0 (core, "o malloc://16; e arch.codealign=1; e anal.mask=false");
	mu_assert_true (r_arch_plugin_add (core->anal->arch, &ao_test_plugin), "register counting decoder");
	mu_assert_true (r_arch_use (core->anal->arch, core->anal->config, "ao-test"), "select counting decoder");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (commands); i++) {
		ao_decode_count = 0;
		char *output = r_core_cmd_str (core, commands[i]);
		free (output);
		mu_assert_eq (ao_decode_count, 3, commands[i]);
		mu_assert_true (ao_decode_mask & R_ARCH_OP_MASK_HINT, "analysis applies hints");
	}
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_decode_invalid_mnemonic);
	mu_run_test (test_ao_single_decode);
	mu_run_test (test_visual_disasm_invalid_sizes);
	mu_run_test (test_visual_disasm_unmapped);
	mu_run_test (test_disasm_without_decoder);
	mu_run_test (test_disasm_truncated_byte_selection);
	mu_run_test (test_disasm_flag_byte_colors);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
