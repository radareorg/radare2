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

static bool all_tests(void) {
	mu_run_test (test_include_preserves_parser_line);
	mu_run_test (test_element_limit);
	mu_run_test (test_compile_element_limit);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
