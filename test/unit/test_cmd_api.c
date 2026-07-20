#include <r_core.h>
#include "minunit.h"

static RCmdResult first_handler(RCmdContext *ctx, RStrs input) {
	(void)ctx;
	(void)input;
	RCmdResult result = { 0 };
	return result;
}

typedef struct {
	size_t stop_after;
	RStrBuf names;
} CmdVisit;

static bool visit_command(RStrs name, void *user) {
	CmdVisit *visit = user;
	return r_strbuf_append_n (&visit->names, name.a, r_strs_len (name))
		&& r_strbuf_append (&visit->names, ",")
		&& (!visit->stop_after || --visit->stop_after);
}

typedef struct {
	void *expected_user;
	const char *expected_input;
	RCmdAction action;
	st64 status;
	int calls;
	int legacy_calls;
	bool context_ok;
} DispatchState;

static RCmdResult dispatch_handler(RCmdContext *ctx, RStrs input) {
	DispatchState *state = ctx->handler_user;
	state->calls++;
	state->context_ok = ctx->cmd && ctx->user == state->expected_user
		&& r_strs_equals_str (input, state->expected_input);
	RCmdResult result = {
		.action = state->action,
		.status = state->status
	};
	return result;
}

static int legacy_handler(void *user, const char *input) {
	DispatchState *state = user;
	state->legacy_calls++;
	return !strcmp (input, "fl?")? 9: -1;
}

static bool test_r_cmd_register(void) {
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "af", first_handler, cmd), "register af");
	mu_assert_true (r_cmd_register (cmd, "afl", first_handler, NULL), "register afl");
	mu_assert_eq (r_trie_size (cmd->handlers), 2, "registered handler count");
	mu_assert_false (r_cmd_register (cmd, "af", first_handler, NULL), "reject duplicate name");
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
	mu_assert_true (r_cmd_register (cmd, "afl", first_handler, NULL), "register afl");
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

static bool test_r_cmd_prefix_registry(void) {
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "af", first_handler, NULL), "register af");
	mu_assert_true (r_cmd_register (cmd, "afl", first_handler, NULL), "register afl");
	mu_assert_true (r_cmd_register (cmd, "aflj", first_handler, NULL), "register aflj");
	mu_assert_true (r_cmd_register (cmd, "agn", first_handler, NULL), "register agn");
	mu_assert_true (r_cmd_register (cmd, "pd", first_handler, NULL), "register pd");
	CmdVisit visit = { 0 };
	r_strbuf_init (&visit.names);
	mu_assert_true (r_cmd_foreach_prefix (cmd, "af", visit_command, &visit), "enumerate af handlers");
	mu_assert_streq (r_strbuf_get (&visit.names), "af,afl,aflj,", "handler names are ordered");
	mu_assert_eq (r_cmd_unregister_prefix (cmd, "afl"), 2, "unregister handler subtree");
	mu_assert_notnull (r_trie_find (cmd->handlers, R_STRS_LIT ("af")), "parent handler remains");
	mu_assert_null (r_trie_find (cmd->handlers, R_STRS_LIT ("afl")), "subtree handler removed");
	mu_assert_eq (r_cmd_unregister_prefix (cmd, "missing"), 0, "unregister missing prefix");
	mu_assert_eq (r_cmd_unregister_prefix (cmd, ""), 3, "empty prefix unregisters all handlers");
	mu_assert_eq (r_trie_size (cmd->handlers), 0, "handler registry empty");
	r_strbuf_fini (&visit.names);
	r_cmd_free (cmd);
	mu_end;
}

static bool test_r_cmd_registry_dispatch(void) {
	DispatchState parent = {
		.expected_input = "afl?",
		.action = R_CMD_ACTION_CONTINUE,
		.status = 7
	};
	DispatchState child = {
		.expected_input = "afl?",
		.action = R_CMD_ACTION_UNHANDLED
	};
	parent.expected_user = child.expected_user = &child;
	RCmd *cmd = r_cmd_new (&child);
	mu_assert_true (r_cmd_register (cmd, "a", dispatch_handler, &parent), "register parent handler");
	mu_assert_true (r_cmd_register (cmd, "af", dispatch_handler, &child), "register child handler");
	mu_assert_eq (r_cmd_call (cmd, "afl?"), 7, "parent handles child fallback");
	mu_assert_eq (child.calls, 1, "longest prefix called first");
	mu_assert_eq (parent.calls, 1, "parent prefix called after unhandled");
	mu_assert_true (child.context_ok && parent.context_ok, "handlers receive context and full input");
	mu_assert_true (r_cmd_unregister (cmd, "a"), "remove registered parent");
	mu_assert_true (r_cmd_add (cmd, "a", legacy_handler), "register legacy fallback");
	mu_assert_eq (r_cmd_call (cmd, "afl?"), 9, "unhandled registry falls back to legacy");
	mu_assert_eq (child.legacy_calls, 1, "legacy fallback called once");
	child.action = R_CMD_ACTION_QUIT;
	mu_assert_eq (r_cmd_call (cmd, "afl?"), -2, "quit action maps to legacy quit code");
	mu_assert_eq (child.legacy_calls, 1, "handled registry skips legacy callback");
	r_cmd_free (cmd);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_cmd_register);
	mu_run_test (test_r_cmd_unregister);
	mu_run_test (test_r_cmd_prefix_registry);
	mu_run_test (test_r_cmd_registry_dispatch);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
