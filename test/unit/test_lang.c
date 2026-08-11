#include <r_lang.h>
#include "minunit.h"

static bool test_lang_plugin_without_name(void) {
	RLang *lang = r_lang_new ();
	mu_assert_notnull (lang, "RLang allocation");

	RLangPlugin plugin = { 0 };
	mu_assert_false (r_lang_plugin_add (lang, &plugin), "reject plugin without name");

	r_lang_free (lang);
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_lang_plugin_without_name);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
