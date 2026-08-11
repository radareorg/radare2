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

static bool all_tests(void) {
	mu_run_test (test_include_preserves_parser_line);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
