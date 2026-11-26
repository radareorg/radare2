#include <r_egg.h>
#include "minunit.h"

static int parse_string(REgg *egg, const char *s) {
	for (; *s; s++) {
		int ret = r_egg_lang_parsechar (egg, *s);
		if (ret) {
			return ret;
		}
	}
	return 0;
}

static bool test_include_preserves_parser_line(void) {
	REgg *egg = r_egg_new ();
	mu_assert_notnull (egg, "r_egg_new failed");
	r_egg_lang_init (egg);

	mu_assert_eq (parse_string (egg, "missing.r@include(INCDIR)"), 0, "include parsing failed");
	mu_assert ("include argument did not reset the element buffer", r_strbuf_is_empty (&egg->lang.elem));
	mu_assert_notnull (egg->lang.includefile, "include state was not preserved until the semicolon");

	egg->lang.line = 0x7f7f7f7f;
	r_log_set_quiet (true);
	int ret = r_egg_lang_parsechar (egg, ';');
	r_log_set_quiet (false);
	mu_assert_eq (ret, 0, "include terminator parsing failed");
	mu_assert_eq (egg->lang.line, 0x7f7f7f7f, "include handling corrupted adjacent parser state");

	r_egg_free (egg);
	mu_end;
}

static bool test_long_elements(void) {
	const char *prefixes[] = { "", "(", ":" };
	size_t i, j;
	for (i = 0; i < R_ARRAY_SIZE (prefixes); i++) {
		REgg *egg = r_egg_new ();
		r_egg_lang_init (egg);
		mu_assert_eq (parse_string (egg, prefixes[i]), 0, "prefix parsing failed");
		for (j = 0; j < 4096; j++) {
			mu_assert_eq (r_egg_lang_parsechar (egg, 'A'), 0, "long element was rejected");
		}
		mu_assert_eq (r_strbuf_length (&egg->lang.elem), 4096, "element was truncated");
		r_egg_free (egg);
	}
	mu_end;
}

static bool test_compile_long_elements(void) {
	const char *formats[] = {
		"%s\n",
		"exit@syscall(60);\n@syscall(){\n: %s\n}\nmain@global(){exit(0); }\n",
		"f@inline(){\n: %s\n}\nmain@global(){f(); }\n",
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (formats); i++) {
		REgg *egg = r_egg_new ();
		mu_assert ("setup failed", r_egg_setup (egg, "trace", 64, 0, "linux"));
		char *element = r_str_repeat ("A", 5000);
		char *source = r_str_newf (formats[i], element);
		r_egg_load (egg, source, 0);
		free (source);
		mu_assert ("long element did not compile", r_egg_compile (egg));
		char *out = r_egg_get_assembly (egg);
		mu_assert ("long element was truncated", !i || strstr (out, element));
		free (out);
		free (element);
		r_egg_free (egg);
	}
	mu_end;
}

static bool test_llvm_output(void) {
	REgg *egg = r_egg_new ();
	mu_assert_notnull (egg, "r_egg_new failed");
	mu_assert ("LLVM setup failed", r_egg_setup (egg, "llvm", 64, 0, NULL));
	r_egg_load (egg, "puts@extern(i32, ptr); main@global(){ puts(\"hello (world), \\\"friend\\\"\\n\"); 0; }", 0);
	mu_assert ("LLVM compilation failed", r_egg_compile (egg));
	char *ir = r_egg_get_assembly (egg);
	mu_assert_notnull (ir, "missing LLVM output");
	mu_assert ("missing typed declaration", strstr (ir, "declare i32 @puts(ptr)"));
	mu_assert ("missing main definition", strstr (ir, "define i32 @main()"));
	mu_assert ("missing typed call", strstr (ir, "call i32 @puts(ptr "));
	mu_assert ("incorrect string bytes", strstr (ir, "c\"hello (world), \\22friend\\22\\0A\\00\""));
	mu_assert ("LLVM recompilation failed", r_egg_compile (egg));
	char *recompiled = r_egg_get_assembly (egg);
	mu_assert_streq (recompiled, ir, "recompilation changed the module");
	free (recompiled);
	free (ir);
	r_egg_reset (egg);
	r_egg_load (egg, "main@global(){ puts(\"missing declaration\"); }", 0);
	r_log_set_quiet (true);
	bool ok = r_egg_compile (egg);
	r_log_set_quiet (false);
	mu_assert ("an undeclared external call was accepted", !ok);
	r_egg_free (egg);
	mu_end;
}

static bool test_llvm_syscalls(void) {
	const char *darwin = "write@syscall(4); exit@syscall(1); main@global(){ write(1, \"hi\", 2); exit(0); }";
	const char *linux_x64 = "write@syscall(1); exit@syscall(60); main@global(){ write(1, \"hi\", 2); exit(0); }";
	const struct {
		const char *os;
		int bits;
		const char *source;
		const char *declaration;
		const char *write_call;
		const char *exit_call;
	} cases[] = {
		{ "darwin", 64, darwin, "declare i32 @syscall(i32, ...)", "@syscall(i32 4, i64 1, i64 ", "@syscall(i32 1, i64 0)" },
		{ "linux", 64, linux_x64, "declare i64 @syscall(i64, ...)", "@syscall(i64 1, i64 1, i64 ", "@syscall(i64 60, i64 0)" },
		{ "linux", 32, darwin, "declare i32 @syscall(i32, ...)", "@syscall(i32 4, i32 ", "@syscall(i32 1, i32 " },
	};
	REgg *egg = r_egg_new ();
	mu_assert_notnull (egg, "r_egg_new failed");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		r_egg_reset (egg);
		mu_assert ("LLVM setup failed", r_egg_setup (egg, "llvm", cases[i].bits, 0, cases[i].os));
		r_egg_load (egg, cases[i].source, 0);
		mu_assert ("LLVM syscall compilation failed", r_egg_compile (egg));
		char *ir = r_egg_get_assembly (egg);
		mu_assert_notnull (ir, "missing LLVM output");
		mu_assert ("wrong syscall ABI", strstr (ir, cases[i].declaration));
		mu_assert ("wrong write syscall", strstr (ir, cases[i].write_call));
		mu_assert ("wrong exit syscall", strstr (ir, cases[i].exit_call));
		free (ir);
	}
	r_egg_free (egg);
	mu_end;
}

static bool test_llvm_inline_assembly(void) {
	REgg *egg = r_egg_new ();
	mu_assert_notnull (egg, "r_egg_new failed");
	mu_assert ("LLVM setup failed", r_egg_setup (egg, "llvm", 32, 0, "linux"));
	r_egg_option_set (egg, "llvm.asm.arch", "x86");
	r_egg_load (egg, "main@global(){\n: nop\n: mov eax, 1\n0;\n}", 0);
	mu_assert ("LLVM assembly compilation failed", r_egg_compile (egg));
	char *ir = r_egg_get_assembly (egg);
	mu_assert_notnull (ir, "missing LLVM output");
	mu_assert ("inline instructions were not assembled together", strstr (ir,
		"asm sideeffect \".byte 0x90, 0xb8, 0x01, 0x00, 0x00, 0x00\""));
	free (ir);
	r_egg_reset (egg);
	r_egg_load (egg, "main@global(){\n: not_an_instruction\n}", 0);
	r_log_set_quiet (true);
	bool ok = r_egg_compile (egg);
	r_log_set_quiet (false);
	mu_assert ("invalid instruction was accepted", !ok);
	r_egg_free (egg);
	mu_end;
}

static char *compile_source(const char *arch, int bits, const char *source) {
	REgg *egg = r_egg_new ();
	r_egg_setup (egg, arch, bits, 0, "linux");
	r_egg_option_set (egg, "llvm.asm.arch", "x86");
	r_egg_load (egg, source, 0);
	r_log_set_quiet (true);
	char *out = r_egg_compile (egg)? r_egg_get_assembly (egg): NULL;
	r_log_set_quiet (false);
	r_egg_free (egg);
	return out;
}

static bool test_statements_and_directives(void) {
	char *asm_ = compile_source ("x86", 64, "puts@extern(i32, ptr);\nmain@global(16,0){\n.var0 = 2;\n.var0 * 3;\n.var0;\n}\n");
	mu_assert_notnull (asm_, "x86 compilation failed");
	mu_assert ("extern emitted a label", !strstr (asm_, "puts:"));
	mu_assert ("expression statement not evaluated", strstr (asm_, "mul rsi, 3"));
	mu_assert ("variable statement not resolved", strstr (asm_, "mov rax, [rbp+8]") && !strstr (asm_, ".var0"));
	free (asm_);
	asm_ = compile_source ("arm", 32, "main@global(){ .var0 = \"a\\\"b\\\\c\"; }");
	mu_assert_notnull (asm_, "arm compilation failed");
	mu_assert ("string escaped twice", strstr (asm_, ".string \"a\\\"b\\\\c\""));
	free (asm_);
	char *big = r_str_repeat (": nop\n", 1000);
	char *source = r_str_newf ("f@inline(){\n%s: int3\n}\nmain@global(){f(); }\n", big);
	asm_ = compile_source ("x86", 64, source);
	mu_assert ("large inline body truncated", asm_ && strstr (asm_, "int3"));
	free (asm_);
	free (source);
	free (big);
	mu_end;
}

static bool test_llvm_statements(void) {
	char *ir = compile_source ("llvm", 64, "add@global(){\n.arg0 + .arg1 * 2;\n}\nmain@global(){\nadd(1, 3);\n}\n");
	mu_assert_notnull (ir, "LLVM expression statement failed");
	mu_assert ("missing multiplication", strstr (ir, "mul i64"));
	mu_assert ("missing addition", strstr (ir, "add i64"));
	mu_assert ("missing typed call", strstr (ir, "call i64 @add(i64 1, i64 3)"));
	free (ir);
	ir = compile_source ("llvm", 64, "msg@data(1){ 1 }\nmain@global(){ 0; }\n");
	mu_assert ("@data was accepted by the LLVM backend", !ir);
	ir = compile_source ("llvm", 64, "main@global(){\n.var0 = 0;\nwhile (.var0 < 3) {\n.var0 += 1;\n}\n.var0;\n}\n");
	mu_assert_notnull (ir, "LLVM loop compilation failed");
	mu_assert ("missing loop back-edge", strstr (ir, "br label %__begin_0_1_0\n__end_0_1_0:"));
	free (ir);
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_include_preserves_parser_line);
	mu_run_test (test_long_elements);
	mu_run_test (test_compile_long_elements);
	mu_run_test (test_llvm_output);
	mu_run_test (test_llvm_syscalls);
	mu_run_test (test_llvm_inline_assembly);
	mu_run_test (test_statements_and_directives);
	mu_run_test (test_llvm_statements);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
