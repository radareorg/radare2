#include <r_core.h>
#include "minunit.h"

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

int all_tests(void) {
	mu_run_test (test_disasm_truncated_byte_selection);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
