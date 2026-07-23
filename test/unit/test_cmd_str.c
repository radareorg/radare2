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

bool test_multiple_cores_share_terminal(void) {
	RCore *first = r_core_new ();
	RCore *second = r_core_new ();
	mu_assert ("different console instances", first->cons != second->cons);
	mu_assert_notnull (first->cons->terminal, "first core console is attached");
	mu_assert_notnull (second->cons->terminal, "second core console is attached");

	char *first_output = r_core_cmd_str (first, "?e first");
	char *second_output = r_core_cmd_str (second, "?e second");
	mu_assert_streq_free (first_output, "first\n", "first core output");
	mu_assert_streq_free (second_output, "second\n", "second core output");

	r_core_free (first);
	mu_assert_ptreq (r_cons_singleton (), second->cons, "freeing first core preserves second");
	r_core_free (second);
	mu_assert_false (r_cons_is_initialized (), "freeing both cores clears current console");
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

bool test_prompt_format_preserves_trailing_escaped_space(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	char *prompt = r_core_prompt_format (core, "R2\\s");
	mu_assert_notnull (prompt, "Prompt format should render");
	mu_assert_streq (prompt, "R2 ", "Trailing escaped space should be preserved");

	free (prompt);
	r_core_free (core);
	mu_end;
}

bool test_prompt_format_preserves_trailing_escaped_newline(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	char *prompt = r_core_prompt_format (core, "R2\\n");
	mu_assert_notnull (prompt, "Prompt format should render");
	mu_assert_streq (prompt, "R2\n", "Trailing escaped newline should be preserved");

	free (prompt);
	r_core_free (core);
	mu_end;
}

bool test_autocomplete_find_prefers_exact_match(void) {
	RCoreAutocomplete *root = R_NEW0 (RCoreAutocomplete);
	RCoreAutocomplete *oe = r_core_autocomplete_add (root, "oe", R_CORE_AUTOCMPLT_FILE, true);
	RCoreAutocomplete *o = r_core_autocomplete_add (root, "o", R_CORE_AUTOCMPLT_FILE, true);
	RCoreAutocomplete *open = r_core_autocomplete_add (root, "open", R_CORE_AUTOCMPLT_FILE, true);
	mu_assert_notnull (oe, "Couldn't add oe autocomplete");
	mu_assert_notnull (o, "Couldn't add o autocomplete");
	mu_assert_notnull (open, "Couldn't add open autocomplete");

	mu_assert_ptreq (r_core_autocomplete_find (root, "o", false), o, "Prefix lookup should prefer exact command matches");
	mu_assert_ptreq (r_core_autocomplete_find (root, "op", false), open, "Prefix lookup should still find longer matches");

	r_core_autocomplete_free (root);
	mu_end;
}

bool test_o_autocomplete_uses_file_completion(void) {
	char *dir = r_file_temp ("r2-ac");
	mu_assert_notnull (dir, "Couldn't create temporary path");
	mu_assert_true (r_sys_mkdir (dir), "Couldn't create temporary directory");

	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	RLineCompletion completion = {0};
	r_line_completion_init (&completion, 16);

	RLineBuffer buf = {0};
	char *cmd = r_str_newf ("o %s", dir);
	mu_assert_notnull (cmd, "Couldn't create autocomplete command");
	r_str_ncpy (buf.data, cmd, sizeof (buf.data));
	buf.length = strlen (buf.data);
	buf.index = buf.length;

	r_core_autocomplete (core, &completion, &buf, R_LINE_PROMPT_DEFAULT);

	char *expected = r_str_newf ("%s%s", dir, R_SYS_DIR);
	mu_assert_notnull (expected, "Couldn't create expected completion");
	bool found = false;
	char **it;
	R_VEC_FOREACH (&completion.args, it) {
		if (!strcmp (*it, expected)) {
			found = true;
			break;
		}
	}

	free (expected);
	free (cmd);
	r_line_completion_clear (&completion);
	RVecCString_fini (&completion.args);
	r_core_free (core);
	r_file_rm (dir);
	free (dir);
	mu_assert_true (found, "o <path> should use file completion");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_cmd_str_issue_18799);
	mu_run_test (test_multiple_cores_share_terminal);
	mu_run_test (test_prompt_utf8_ellipsis_width);
	mu_run_test (test_prompt_format_preserves_trailing_escaped_space);
	mu_run_test (test_prompt_format_preserves_trailing_escaped_newline);
	mu_run_test (test_autocomplete_find_prefers_exact_match);
	mu_run_test (test_o_autocomplete_uses_file_completion);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
