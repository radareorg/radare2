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

int all_tests(void) {
	mu_run_test (test_disasm_truncated_byte_selection);
	mu_run_test (test_disasm_flag_byte_colors);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
