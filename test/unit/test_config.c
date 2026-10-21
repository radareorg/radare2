#include <r_config.h>
#include "minunit.h"

bool test_config_newlines(void) {
	RConfig *cfg = r_config_new (NULL);
	mu_assert_notnull (r_config_set (cfg, "existing", "42"), "create config value");
	const char *invalid[] = { "\n", "\r", "42\n!id", "42\r!id", "42\r\n!id" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (invalid); i++) {
		mu_assert_null (r_config_set (cfg, "new", invalid[i]), "reject new multiline value");
		mu_assert_null (r_config_node_get (cfg, "new"), "rejected value creates no node");
		mu_assert_null (r_config_set (cfg, "existing", invalid[i]), "reject multiline update");
		mu_assert_streq (r_config_get (cfg, "existing"), "42", "preserve string value");
		mu_assert_eq (r_config_get_i (cfg, "existing"), 42, "preserve numeric value");
	}
	mu_assert_notnull (r_config_set (cfg, "existing", "quoted \"value\"; text"), "accept single-line value");
	mu_assert_streq (r_config_get (cfg, "existing"), "quoted \"value\"; text", "preserve single-line value");
	mu_assert_notnull (r_config_set (cfg, "existing", ""), "accept empty value");
	mu_assert_streq (r_config_get (cfg, "existing"), "", "store empty value");
	r_config_free (cfg);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_config_newlines);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
