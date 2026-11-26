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
	mu_assert_eq (egg->lang.elem_n, 0, "include argument did not reset the element buffer");
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

static bool test_element_limit(void) {
	const char *prefixes[] = { "", "", "", "(", ":`" };
	const char next[] = { 'A', ':', '/', 'A', 'A' };
	size_t i, j;
	for (i = 0; i < R_ARRAY_SIZE (prefixes); i++) {
		REgg *egg = r_egg_new ();
		r_egg_lang_init (egg);
		mu_assert_eq (parse_string (egg, prefixes[i]), 0, "prefix parsing failed");
		for (j = 0; j < sizeof (egg->lang.elem) - 1; j++) {
			mu_assert_eq (r_egg_lang_parsechar (egg, 'A'), 0, "element rejected before the limit");
		}
		egg->lang.attsyntax = 0x1234;
		r_log_set_quiet (true);
		int ret = r_egg_lang_parsechar (egg, next[i]);
		r_log_set_quiet (false);
		mu_assert_eq (ret, -1, "oversized element was accepted");
		mu_assert_eq (egg->lang.elem_n, sizeof (egg->lang.elem) - 1, "element length changed on failure");
		mu_assert_eq (egg->lang.elem[egg->lang.elem_n], 0, "element is not terminated");
		mu_assert_eq (egg->lang.attsyntax, 0x1234, "element overflow corrupted adjacent state");
		r_egg_free (egg);
	}
	mu_end;
}

static bool test_compile_element_limit(void) {
	const char *formats[] = {
		"%s\n",
		"exit@syscall(60);\n@syscall(){\n%s\n}\nmain@global(){exit(0); }\n",
		"f@inline(){\n%s\n}\nmain@global(){f(); }\n",
	};
	const size_t lengths[] = { 1022, 1023, 1024, 1100 };
	size_t i, j;
	for (i = 0; i < R_ARRAY_SIZE (formats); i++) {
		for (j = 0; j < R_ARRAY_SIZE (lengths); j++) {
			REgg *egg = r_egg_new ();
			mu_assert ("setup failed", r_egg_setup (egg, "x86", 64, 0, "linux"));
			char *element = r_str_repeat ("A", lengths[j]);
			char *source = r_str_newf (formats[i], element);
			r_egg_load (egg, source, 0);
			free (source);
			free (element);
			r_log_set_quiet (true);
			bool ret = r_egg_compile (egg);
			r_log_set_quiet (false);
			size_t replay_newline = i? 1: 0;
			mu_assert_eq (ret, lengths[j] + replay_newline < sizeof (egg->lang.elem), "incorrect compilation result at element limit");
			r_egg_free (egg);
		}
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

static bool all_tests(void) {
	mu_run_test (test_include_preserves_parser_line);
	mu_run_test (test_element_limit);
	mu_run_test (test_compile_element_limit);
	mu_run_test (test_llvm_output);
	mu_run_test (test_llvm_syscalls);
	mu_run_test (test_llvm_inline_assembly);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
