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

static bool test_assembly_strings(void) {
	const struct {
		const char *source;
		const char *hex;
	} cases[] = {
		{ ".ascii \"a#b;c,,d\"", "6123623b632c2c64" },
		{ ".ascii \"$$:$sys.write\"", "24243a247379732e7772697465" },
		{ ".ascii \"a\\\"#;b\\\\n\"", "6122233b625c6e" },
		{ ".ascii \"A\\x00B\"", "410042" },
		{ ".ascii \"\"; .string \"\"", "00" },
		{ ".asciz\t\"AB\"; .asciiz \"C\"; .string\t\"D\"", "41420043004400" },
		{ ".ascii \"#;\" ; comment with \"\n.ascii \"B\"\n", "233b42" },
		{ ".ascii \"A\" # comment with \"\n.ascii \"B\"\n", "4142" },
		{ ".ascii \"A\" /* comment with \" */; .ascii \"B\"", "4142" },
		{ "start:; .ascii \"#;\"; end:; .uint16 end-start", "233b0200" },
		{ ".uint16 $$; .ascii \"$$\"", "00002424" },
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < 2 * R_ARRAY_SIZE (cases); i++) {
		a->use_spp = i >= R_ARRAY_SIZE (cases);
		r_asm_set_pc (a, 0);
		const size_t n = i % R_ARRAY_SIZE (cases);
		RAsmCode *code = r_asm_assemble (a, cases[n].source);
		mu_assert_notnull (code, cases[n].source);
		char *hex = r_hex_bin2strdup (code->bytes, code->len);
		mu_assert_streq (hex, cases[n].hex, cases[n].source);
		free (hex);
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_string_errors(void) {
	const char *sources[] = {
		".ascii",
		".ascii unquoted",
		".ascii \"unterminated",
		".ascii \"A\" trailing",
		".ascii \"A\", \"B\"",
		".ascii \"\\x\"",
		".ascii \"\\x4\"",
		".ascii \"\\xgg\"",
		".ascizextra \"A\"",
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		RAsmCode *code = r_asm_assemble (a, sources[i]);
		mu_assert_null (code, sources[i]);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_charsets(void) {
	const struct {
		const char *source;
		const char *hex;
	} cases[] = {
		{ ".charset \"pokered\"; .ascii \"A<LINE>B\"; .byte 0x50", "804f8150" },
		{ ".charset \"pokered\"; .string \"Aé?\"", "80e0e600" },
		{ ".charset\t\"ebcdic37\"; .asciiz\t\"ABé\"", "c1c25100" },
		{ ".charset \"base64\"; .string \"AB\"", "5155493d00" },
		{ ".charset \"base64\"; .ascii \"A\"; .ascii \"B\"", "51513d3d51673d3d" },
		{ ".charset \"base64\"; .ascii \"\\xff\"", "2f773d3d" },
		{ ".charset \"pokered\"; .ascii \"A\"; .charset \"raw\"; .string \"A\"", "804100" },
		{ ".charset \"ebcdic37\"; .string \"A\\x00B\"", "c100c200" },
		{ ".charset \"base64\"; .ascii \"A\\x00B\"", "51514243" },
		{ ".charset \"ebcdic37\"; .ascii \"\\\\n\"", "e095" },
		{ ".charset \"pokered\"; .asciz \"\"; .ascii \"\"; .asciiz \"\"; .string \"\"", "000000" },
		{ ".charset \"base64\"; .string \"\"", "00" },
		{ ".ascii \"A\"; .charset \"base64\"; .ascii \"AB\"; end:; .uint16 end", "415155493d0500" },
		{ ".charset \"pokered\"; .byte 65; .hex 4243; .ascii \"A\"", "41424380" },
		{ ".equ pokered, missing; .charset \"pokered\"; .ascii \"A\"", "80" },
		{ ".charset \"raw\"; .ascii \"\\xff\"", "ff" },
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < 2 * R_ARRAY_SIZE (cases); i++) {
		a->use_spp = i >= R_ARRAY_SIZE (cases);
		r_asm_set_pc (a, 0);
		const size_t n = i % R_ARRAY_SIZE (cases);
		RAsmCode *code = r_asm_assemble (a, cases[n].source);
		mu_assert_notnull (code, cases[n].source);
		char *hex = r_hex_bin2strdup (code->bytes, code->len);
		mu_assert_streq (hex, cases[n].hex, cases[n].source);
		free (hex);
		r_asm_code_free (code);
		code = r_asm_assemble (a, ".string \"AB\"");
		mu_assert_notnull (code, "new assembly resets charset");
		mu_assert_eq (code->len, 3, "raw length after encoded assembly");
		mu_assert_memeq (code->bytes, (const ut8 *)"AB", 3, "raw bytes after encoded assembly");
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_charset_errors(void) {
	const char *sources[] = {
		".charset \"missing\"",
		".ascii \"A\"; .charset \"missing\"",
		".charset \"pokered\"; .charset \"missing\"; .string \"AB\"",
		".charset \"ascii.oem\"",
		".charset \"aes\"",
		".charset \"sha256\"",
		".charset \"\"",
		".charset \"raw\\x00missing\"",
		".charset",
		".charset raw",
		".charsetx \"raw\"",
		".charset \"raw\" trailing",
		".charset \"pokered\"; .ascii \"A☃\"",
		".charset \"pokered\"; .ascii \"A\\x00B\"",
		".charset \"pokered\"; .ascii \"A\\xc3\"",
		".charset \"ebcdic37\"; .ascii \"A☃\"",
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		RAsmCode *code = r_asm_assemble (a, sources[i]);
		mu_assert_null (code, sources[i]);
		code = r_asm_assemble (a, ".ascii \"AB\"");
		mu_assert_notnull (code, "assembly after failure succeeds");
		mu_assert_eq (code->len, 2, "charset reset after failure");
		mu_assert_memeq (code->bytes, (const ut8 *)"AB", 2, "raw bytes after failure");
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_byte_expressions(void) {
	const struct {
		const char *source;
		const char *hex;
	} cases[] = {
		{ ".byte 1 + 2, 3", "0303" },
		{ ".db (1 + 2) * 3, 4", "0904" },
		{ ".int8 1 << 4, (0xf0 >> 4) | 0x80", "108f" },
		{ ".byte \t1\t+\t2 ,\t3\t", "0303" },
		{ ".byte -(-1), +2, 0, 255", "010200ff" },
		{ ".equ X, 2; .byte X * 3, (X + 1) * 2", "0606" },
		{ "base:; .byte end - base, end - base + 1; end:; .byte 0", "020300" },
	};
	RAsm *a = r_asm_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		r_asm_set_pc (a, 0);
		RAsmCode *code = r_asm_assemble (a, cases[i].source);
		mu_assert_notnull (code, cases[i].source);
		char *hex = r_hex_bin2strdup (code->bytes, code->len);
		mu_assert_streq (hex, cases[i].hex, cases[i].source);
		free (hex);
		r_asm_code_free (code);
	}
	r_asm_free (a);
	mu_end;
}

static bool test_assembly_byte_expression_errors(void) {
	const char *sources[] = {
		".byte 1 2",
		".db 1\t2",
		".int8 1 + 2 3",
		".byte 1,",
		".db ,1",
		".int8 1, ,2",
		".byte 1, missing",
		".byte 256",
		".byte -1",
		".byte 0x100000000",
		".byte 1, (2",
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
	RAsmCode *code = r_asm_assemble (a, ".org 4096, 0xa5; tail:; .uint16 tail-4096");
	mu_assert_notnull (code, "padding larger than the inline operation buffer");
	mu_assert_eq (code->len, 4098, "large padding length");
	for (i = 0; i < 4096; i++) {
		mu_assert_eq (code->bytes[i], 0xa5, "large padding bytes");
	}
	mu_assert_eq (code->bytes[4096], 0, "label offset low byte");
	mu_assert_eq (code->bytes[4097], 0, "label offset high byte");
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
	mu_run_test (test_assembly_strings);
	mu_run_test (test_assembly_string_errors);
	mu_run_test (test_assembly_charsets);
	mu_run_test (test_assembly_charset_errors);
	mu_run_test (test_assembly_byte_expressions);
	mu_run_test (test_assembly_byte_expression_errors);
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
