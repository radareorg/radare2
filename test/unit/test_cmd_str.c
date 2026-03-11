#include <r_core.h>
#include "minunit.h"

static int test_user_fgets(RCons *cons, char *buf, int len) {
	(void)cons;
	if (len > 0) {
		*buf = '\0';
	}
	return 0;
}

bool test_cmd_str_issue_18799(void) {
	RCore *core = r_core_new ();
	char *output = r_core_cmd_str (core, "pd 1 @e:asm.hints=false");
	mu_assert ("command output leaked to stdout", strlen (output) > 0);
	free (output);
	r_core_free (core);
	mu_end;
}

bool test_prompt_utf8_ellipsis_width(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	core->cons->force_columns = 16;
	core->cons->force_rows = 1;
	core->cons->user_fgets = test_user_fgets;

	r_config_set_b (core->config, "scr.prompt.code", false);
	r_config_set_b (core->config, "scr.prompt.file", false);
	r_config_set_b (core->config, "scr.prompt.prj", false);
	r_config_set_b (core->config, "scr.prompt.flag", false);
	r_config_set_b (core->config, "scr.prompt.sect", false);
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", true);
	r_config_set (core->config, "cmd.prompt", "");
	r_config_set (core->config, "scr.prompt.format", "");

	mu_assert_true (r_core_prompt (core, false), "Prompt should render");
	char *prompt = r_line_get_prompt (core->cons->line);
	mu_assert_streq (prompt, "[0x0000…]> ", "Prompt should budget ellipsis by display width");

	free (prompt);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_cmd_str_issue_18799);
	mu_run_test (test_prompt_utf8_ellipsis_width);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
