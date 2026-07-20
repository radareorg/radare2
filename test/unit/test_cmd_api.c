#include <r_core.h>
#include "minunit.h"

static RCmdResult first_handler(RCmdContext *ctx, RStrs input) {
	(void)ctx;
	(void)input;
	RCmdResult result = { 0 };
	return result;
}

static RCmdResult second_handler(RCmdContext *ctx, RStrs input) {
	(void)ctx;
	(void)input;
	RCmdResult result = { 0 };
	return result;
}

static bool test_r_cmd_register(void) {
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "af", first_handler, cmd), "register af");
	mu_assert_true (r_cmd_register (cmd, "afl", second_handler, NULL), "register afl");
	mu_assert_eq (r_trie_size (cmd->handlers), 2, "registered handler count");
	mu_assert_false (r_cmd_register (cmd, "af", second_handler, NULL), "reject duplicate name");
	mu_assert_eq (r_trie_size (cmd->handlers), 2, "duplicate keeps handler count");
	mu_assert_false (r_cmd_register (cmd, "", first_handler, NULL), "reject empty name");
	mu_assert_false (r_cmd_register (cmd, "af l", first_handler, NULL), "reject whitespace");
	mu_assert_false (r_cmd_register (cmd, "af\tl", first_handler, NULL), "reject tab");
	mu_assert_true (r_cmd_register (cmd, "?", first_handler, NULL), "accept punctuation");
	mu_assert_true (r_cmd_register (cmd, "cmd-ñ", first_handler, NULL), "accept utf8");
	r_cmd_free (cmd);
	mu_end;
}

static bool test_r_cmd_unregister(void) {
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "af", first_handler, NULL), "register af");
	mu_assert_true (r_cmd_register (cmd, "afl", second_handler, NULL), "register afl");
	mu_assert_true (r_cmd_unregister (cmd, "af"), "unregister exact name");
	mu_assert_eq (r_trie_size (cmd->handlers), 1, "exact removal keeps descendant");
	mu_assert_null (r_trie_find (cmd->handlers, R_STRS_LIT ("af")), "af removed");
	mu_assert_notnull (r_trie_find (cmd->handlers, R_STRS_LIT ("afl")), "afl remains");
	mu_assert_false (r_cmd_unregister (cmd, "af"), "reject missing name");
	mu_assert_false (r_cmd_unregister (cmd, ""), "reject empty name");
	mu_assert_true (r_cmd_unregister (cmd, "afl"), "unregister descendant");
	mu_assert_eq (r_trie_size (cmd->handlers), 0, "registry empty");
	r_cmd_free (cmd);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_cmd_register);
	mu_run_test (test_r_cmd_unregister);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
