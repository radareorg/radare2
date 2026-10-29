#include <r_asm.h>
#include "minunit.h"

static bool test_equ_tokens(void) {
	RAsmCode *code = r_asm_code_new ();
	r_asm_code_set_equ (code, "name", "0x1234");
	r_asm_code_set_equ (code, "name_more", "0x5678");
	char *str = r_asm_code_equ_replace (code, "name:name_more, [name+2] rename name.more; name");
	mu_assert_streq (str, "0x1234:0x5678, [0x1234+2] rename name.more; 0x1234", "complete tokens and colon boundary");
	free (str);
	str = r_asm_code_equ_replace (code, "ld a, 0x12");
	mu_assert_streq (str, "ld a, 0x12", "unmatched tokens");
	free (str);
	r_asm_code_free (code);
	mu_end;
}

static bool test_equ_aliases(void) {
	RAsmCode *code = r_asm_code_new ();
	r_asm_code_set_equ (code, "outer", "inner+2");
	r_asm_code_set_equ (code, "inner", "target");
	r_asm_code_set_equ (code, "target", "0x1000");
	char *str = r_asm_code_equ_replace (code, "outer, inner, outer");
	mu_assert_streq (str, "0x1000+2, 0x1000, 0x1000+2", "nested aliases and repeated references");
	free (str);
	r_asm_code_set_equ (code, "empty", "");
	str = r_asm_code_equ_replace (code, "empty+target");
	mu_assert_streq (str, "+0x1000", "empty replacement");
	free (str);
	r_asm_code_set_equ (code, "self", "self");
	r_asm_code_set_equ (code, "cycle_a", "cycle_b");
	r_asm_code_set_equ (code, "cycle_b", "cycle_a");
	str = r_asm_code_equ_replace (code, "self cycle_a");
	mu_assert_streq (str, "self cycle_a", "cyclic references stay unresolved");
	free (str);
	r_asm_code_free (code);
	mu_end;
}

static bool test_equ_long_names(void) {
	RAsmCode *code = r_asm_code_new ();
	char name[300];
	memset (name, 'x', sizeof (name) - 1);
	name[sizeof (name) - 1] = 0;
	r_asm_code_set_equ (code, name, "0x42");
	char *str = r_asm_code_equ_replace (code, name);
	mu_assert_streq (str, "0x42", "long symbol lookup");
	free (str);
	str = r_asm_code_equ_replace (code, "");
	mu_assert_streq (str, "", "empty input");
	free (str);
	r_asm_code_free (code);
	mu_end;
}

static bool test_assembly_delimiters(void) {
	const char *sources[] = {
		".byte 1\n.byte 2; .byte 3",
		".byte 1\r\n.byte 2\r.byte 3\n",
		".byte 1,,.byte 2,,.byte 3",
		".byte 1\n; comment\n.byte 2\n.byte 3\n",
	};
	const ut8 expected[] = { 1, 2, 3 };
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		RAsmCode *code = r_asm_assemble (a, sources[i]);
		mu_assert_notnull (code, "assemble mixed separators");
		mu_assert_eq (code->len, sizeof (expected), "all directives emitted");
		mu_assert_memeq (code->bytes, expected, sizeof (expected), "separator order");
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_equ_tokens);
	mu_run_test (test_equ_aliases);
	mu_run_test (test_equ_long_names);
	mu_run_test (test_assembly_delimiters);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
