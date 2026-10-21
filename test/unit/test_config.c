#include <r_config.h>
#include "minunit.h"

static bool count_setter(void *user, void *data) {
	int *calls = user;
	(*calls)++;
	return true;
}

bool test_config_reject_newlines(void) {
	int calls = 0;
	RConfig *cfg = r_config_new (&calls);
	RConfigNode *node = r_config_set_cb (cfg, "existing", "42", count_setter);
	mu_assert_notnull (node, "create existing node");
	const char *values[] = { "\n", "\r", "a\nb", "a\rb", "a\r\nb", "end\n", "\rstart" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (values); i++) {
		R_DIRTY_UNSET (cfg);
		mu_assert_null (r_config_set (cfg, "existing", values[i]), "reject update with newline");
		mu_assert_streq (node->value, "42", "preserve previous value");
		mu_assert_eq (node->i_value, 42, "preserve previous integer value");
		mu_assert_null (r_config_set_cb (cfg, "new", values[i], count_setter), "reject creation with newline");
		mu_assert_null (r_config_node_get (cfg, "new"), "do not insert rejected node");
		mu_assert_eq (calls, 1, "do not call setter for rejected value");
		mu_assert_false (R_DIRTY_CHECK (cfg), "rejection does not dirty config");
	}
	mu_assert_notnull (r_config_set (cfg, "existing", "café\tvalue"), "accept UTF-8 and tabs");
	mu_assert_streq (node->value, "café\tvalue", "preserve allowed bytes");
	mu_assert_notnull (r_config_set (cfg, "existing", ""), "accept empty value");
	mu_assert_notnull (r_config_set (cfg, "existing", NULL), "preserve NULL reset behavior");
	r_config_free (cfg);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_config_reject_newlines);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
