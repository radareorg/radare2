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
	RCmdContext *expected_parent;
	RCons *expected_cons;
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
		&& ctx->parent == state->expected_parent && ctx->cons == state->expected_cons
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

typedef struct {
	const char *expected_input;
	RStrs *expected_args;
	size_t expected_argc;
	int calls;
	bool args_ok;
} ArgsState;

static RCmdResult args_handler(RCmdContext *ctx, RStrs input) {
	ArgsState *state = ctx->handler_user;
	state->calls++;
	state->args_ok = r_strs_equals_str (input, state->expected_input)
		&& RVecRStrs_length (&ctx->args) == state->expected_argc;
	size_t i;
	for (i = 0; state->args_ok && i < state->expected_argc; i++) {
		RStrs *arg = RVecRStrs_at (&ctx->args, i);
		state->args_ok = arg && r_strs_equals (*arg, state->expected_args[i])
			&& arg->a >= ctx->args_storage.a && arg->b <= ctx->args_storage.b;
	}
	RCmdResult result = { 0 };
	return result;
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
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "create borrowed console");
	RCmd *cmd = r_cmd_new (&child);
	cmd->cons = parent.expected_cons = child.expected_cons = cons;
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
	child.action = R_CMD_ACTION_ABORT;
	mu_assert_eq (r_cmd_call (cmd, "afl?"), -1, "abort action maps to legacy failure");
	mu_assert_eq (child.legacy_calls, 1, "abort skips legacy callback");
	r_cmd_free (cmd);
	r_cons_free (cons);
	mu_end;
}

static bool test_r_cmd_context_args(void) {
	const char binary[] = { 'A', 0, 'A' };
	RStrs expected[] = {
		R_STRS_LIT ("one"),
		R_STRS_LIT ("two three"),
		R_STRS_LIT ("four five"),
		R_STRS_LIT ("say\"hi"),
		R_STRS_LIT ("it's"),
		R_STRS_LIT ("a\\b"),
		R_STRS_LIT (""),
		R_STRS_LIT ("prexpost"),
		R_STRS_LIT ("single value"),
		R_STRS_LIT ("Hello;world"),
		R_STRS_LIT (";you rock"),
		R_STRS_LIT ("A\n"),
		R_STRS_LIT ("ZZ"),
		r_strs_from_len (binary, sizeof (binary))
	};
	const char *input = "cmd one \"two three\" four\\ five say\\\"hi it\\'s a\\\\b '' pre\"x\"post 'single value' \"Hello;world\" \";you rock\" \"\\x41\\n\" \\xZZ \"\\x41\\x00\\x41\"";
	ArgsState state = {
		.expected_input = input,
		.expected_args = expected,
		.expected_argc = R_ARRAY_SIZE (expected)
	};
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "cmd", args_handler, &state), "register argument handler");
	mu_assert_eq (r_cmd_call (cmd, input), 0, "dispatch normalized arguments");
	mu_assert_true (state.args_ok, "arguments are decoded slices of one storage");
	state.expected_input = "cmd";
	state.expected_args = NULL;
	state.expected_argc = 0;
	mu_assert_eq (r_cmd_call (cmd, "cmd"), 0, "dispatch empty argument vector");
	mu_assert_true (state.args_ok, "empty argument vector is available");
	RStrs raw_expected[] = { R_STRS_LIT ("unterminated") };
	state.expected_input = "cmd 'unterminated";
	state.expected_args = raw_expected;
	state.expected_argc = R_ARRAY_SIZE (raw_expected);
	mu_assert_eq (r_cmd_call (cmd, state.expected_input), 0, "raw dispatch accepts unmatched quote");
	mu_assert_true (state.args_ok, "raw dispatch receives best-effort metadata");
	r_cmd_free (cmd);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_cmd_register);
	mu_run_test (test_r_cmd_unregister);
	mu_run_test (test_r_cmd_prefix_registry);
	mu_run_test (test_r_cmd_registry_dispatch);
	mu_run_test (test_r_cmd_context_args);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
