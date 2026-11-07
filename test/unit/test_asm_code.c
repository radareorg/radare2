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
		".byte 1; .byte 2\n.byte 3",
		".byte 1; .byte 2; .byte 3",
		".byte 1\r\n.byte 2\r.byte 3\n",
		".byte 1,,.byte 2,,.byte 3",
		".byte 1\n; comment\n.byte 2\n.byte 3\n",
	};
	const ut8 expected[] = { 1, 2, 3 };
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < 2 * R_ARRAY_SIZE (sources); i++) {
		a->use_spp = i >= R_ARRAY_SIZE (sources);
		RAsmCode *code = r_asm_assemble (a, sources[i % R_ARRAY_SIZE (sources)]);
		mu_assert_notnull (code, "assemble mixed separators");
		mu_assert_eq (code->len, sizeof (expected), "all directives emitted");
		mu_assert_memeq (code->bytes, expected, sizeof (expected), "separator order");
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_org(void) {
	const struct {
		ut64 pc;
		const char *source;
		const char *hex;
	} cases[] = {
		{ 0, ".byte 1; .org 8; here:; .uint16 here", "010800" },
		{ 0, ".byte 1; .org 0; here:; .uint16 here", "010000" },
		{ 0, ".byte 1; .org 8, 0xff; here:; .uint16 here", "01ffffffffffffff0800" },
		{ 0, ".byte 1; .org 1, 0xff; .byte 2; .org 4, 0", "01020000" },
		{ 0, ".org 4, 0xff", "ffffffff" },
		{ 0, ".org 0, 0xff; .byte 1", "01" },
		{ 0, ".org 0x100; .byte 1; .org 0x104, 0xff; here:; .uint16 here", "01ffffff0401" },
		{ 0x100, ".byte 1; .org 0x104, 0xff; here:; .uint16 here", "01ffffff0401" },
		{ 0x100000000, ".byte 1; .org 0x100000004, 0xff; .byte 2", "01ffffff02" },
		{ 0, ".equ target, 4; .equ fill, 0xf0; .byte 1; .org target, fill+15; .byte 2", "01ffffff02" },
		{ 0, "base:; .byte 1; .org base+4, 0xff; here:; .uint16 here", "01ffffff0400" },
		{ 0, ".endian 1; .byte 1; .org 4, 0xff; here:; .uint16 here", "01ffffff0004" },
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		r_asm_set_pc (a, cases[i].pc);
		r_asm_set_big_endian (a, false);
		RAsmCode *code = r_asm_assemble (a, cases[i].source);
		mu_assert_notnull (code, cases[i].source);
		char *hex = r_hex_bin2strdup (code->bytes, code->len);
		mu_assert_streq (hex, cases[i].hex, cases[i].source);
		free (hex);
		r_asm_code_free (code);
	}
	r_asm_set_pc (a, 0);
	RAsmCode *code = r_asm_assemble (a, ".org 128, 0xa5");
	mu_assert_notnull (code, "padding larger than the inline operation buffer");
	mu_assert_eq (code->len, 128, "large padding length");
	for (i = 0; i < 128; i++) {
		mu_assert_eq (code->bytes[i], 0xa5, "large padding bytes");
	}
	r_asm_code_free (code);
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_org_errors(void) {
	const char *sources[] = {
		".byte 1; .org 0, 0xff",
		".org 0x100; .org 0xff, 0",
		".org 0x80000000, 0",
		".org 0xffffffffffffffff, 0",
		".org 4, 256",
		".org 4, -1",
		".org 4,",
		".org , 0xff",
		".org 4, 0, 1",
		".org unknown, 0",
		".org 4, unknown",
		".org unknown",
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		r_asm_set_pc (a, 0);
		RAsmCode *code = r_asm_assemble (a, sources[i]);
		mu_assert_null (code, sources[i]);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_preprocessor_sources(void) {
	const char *sources[] = {
		".set R2_ASM_TEST 1\n.if R2_ASM_TEST\n.byte 1\n.else\n.byte 2\n.endif\n",
		".set R2_ASM_TEST 0\n.if R2_ASM_TEST\n.if R2_ASM_TEST\n.else\n.set R2_ASM_TEST 1\n.error skipped\n.include /missing\n.endif\n.endif\n.if R2_ASM_TEST\n.byte 2\n.else\n.byte 1\n.endif\n",
		".set\tR2_ASM_TEST\t1 ; enabled\n  .ifeq\tR2_ASM_TEST\t1 # selected\n.byte 1\n.endif ; done\n",
		".set R2_ASM_TEST .byte 2-1\n.get R2_ASM_TEST\n",
		".set R2_ASM_TEST 2-1\n.byte .get R2_ASM_TEST\n",
		".set R2_ASM_TEST 1\n.byte .get R2_ASM_TEST",
		"; .error comment\n# .error comment\n/*\n.error comment\n*/\n.byte 1\n",
		".set R2_ASM_TEST 2\n.ifeq\tR2_ASM_TEST\t1\n.byte 2\n.else\n.byte 1\n.endif\n",
		".set R2_ASM_TEST 2\n.ifeq R2_ASM_TEST    2\n.byte 1\n.else\n.byte 2\n.endif\n",
		"<{set R2_ASM_TEST 0}><{ifnot R2_ASM_TEST}>\n.byte 1\n<{else}>\n.byte 2\n<{endif}>\n",
		"<{set R2_ASM_TEST 1}><{switch R2_ASM_TEST}><{case 0}>\n.byte 2\n<{case 1}>\n.byte 1\n<{endswitch}>\n",
	};
	RAsm *a = r_asm_new ();
	a->use_spp = true;
	char *saved = r_sys_getenv ("R2_ASM_TEST");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		RAsmCode *code = r_asm_assemble (a, sources[i]);
		mu_assert_notnull (code, "preprocessor selects valid source");
		mu_assert_eq (code->len, 1, "one selected byte");
		mu_assert_eq (code->bytes[0], 1, "selected branch and exact variable value");
		r_asm_code_free (code);
	}
	RAsmCode *code = r_asm_assemble (a, ".ascii \".if R2_ASM_TEST\"\n.byte 1\n");
	const ut8 expected[] = ".if R2_ASM_TEST\x01";
	mu_assert_notnull (code, "quoted directives stay literal");
	mu_assert_eq (code->len, sizeof (expected) - 1, "literal length");
	mu_assert_memeq (code->bytes, expected, sizeof (expected) - 1, "literal bytes");
	r_asm_code_free (code);
	r_asm_set_pc (a, 0);
	code = r_asm_assemble (a, "label.get:\n.byte 1\n.uint16 label.get\n");
	const ut8 symbol_bytes[] = { 1, 0, 0 };
	mu_assert_notnull (code, "dot in a symbol is not a preprocessor directive");
	mu_assert_eq (code->len, sizeof (symbol_bytes), "symbol length");
	mu_assert_memeq (code->bytes, symbol_bytes, sizeof (symbol_bytes), "symbol bytes");
	r_asm_code_free (code);
	r_sys_setenv ("R2_ASM_TEST", saved);
	free (saved);
	r_asm_free (a);
	mu_end;
}

static bool test_preprocessor_errors(void) {
	const char *sources[] = {
		".error intentional\n.byte 1\n",
		".include /missing-r2-asm-test\n.byte 1\n",
		".endif\n.byte 1\n",
		".else\n.byte 1\n",
		".if R2_ASM_TEST\n.else\n.else\n.endif\n.byte 1\n",
		".if R2_ASM_TEST\n.byte 1\n",
		"<{if R2_ASM_TEST\n.byte 1\n",
		".ifdef R2_ASM_TEST\n.byte 1\n",
	};
	RAsm *a = r_asm_new ();
	a->use_spp = true;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		RAsmCode *code = r_asm_assemble (a, sources[i]);
		mu_assert_null (code, "preprocessor error must reject the whole assembly");
		code = r_asm_assemble (a, ".byte 7\n");
		mu_assert_notnull (code, "next assembly recovers after a preprocessor error");
		mu_assert_eq (code->len, 1, "recovery length");
		mu_assert_eq (code->bytes[0], 7, "recovery bytes");
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_preprocessor_nesting(void) {
	RAsm *a = r_asm_new ();
	a->use_spp = true;
	char *saved = r_sys_getenv ("R2_ASM_TEST");
	r_sys_setenv ("R2_ASM_TEST", "1");
	int depth;
	for (depth = 127; depth <= 128; depth++) {
		RStrBuf source = {0};
		int i;
		for (i = 0; i < depth; i++) {
			r_strbuf_append (&source, ".if R2_ASM_TEST\n");
		}
		r_strbuf_append (&source, ".byte 1\n");
		for (i = 0; i < depth; i++) {
			r_strbuf_append (&source, ".endif\n");
		}
		RAsmCode *code = r_asm_assemble (a, r_strbuf_get (&source));
		if (depth == 127) {
			mu_assert_notnull (code, "maximum conditional nesting");
			mu_assert_eq (code->len, 1, "deep branch emits one byte");
		} else {
			mu_assert_null (code, "conditional depth overflow is rejected before indexing");
		}
		r_asm_code_free (code);
		r_strbuf_fini (&source);
	}
	r_sys_setenv ("R2_ASM_TEST", saved);
	free (saved);
	r_asm_free (a);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_equ_tokens);
	mu_run_test (test_equ_aliases);
	mu_run_test (test_equ_long_names);
	mu_run_test (test_assembly_delimiters);
	mu_run_test (test_assembly_org);
	mu_run_test (test_assembly_org_errors);
	mu_run_test (test_preprocessor_sources);
	mu_run_test (test_preprocessor_errors);
	mu_run_test (test_preprocessor_nesting);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
