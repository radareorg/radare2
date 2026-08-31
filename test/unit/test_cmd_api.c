#include <r_core.h>
#include "minunit.h"

static RCmdResult first_handler(RCmdContext *ctx) {
	(void)ctx;
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
	const char *expected_subcmd;
	RCmdAction action;
	st64 status;
	int calls;
	int legacy_calls;
	bool context_ok;
} DispatchState;

static RCmdResult dispatch_handler(RCmdContext *ctx) {
	DispatchState *state = ctx->handler_user;
	state->calls++;
	state->context_ok = ctx->cmd && ctx->user == state->expected_user
		&& ctx->parent == state->expected_parent && ctx->cons == state->expected_cons
		&& r_strs_equals_str (ctx->subcmd, state->expected_subcmd)
		&& !*ctx->subcmd.b
		&& r_cmd_ctx_help (ctx) && r_cmd_ctx_mode (ctx, "lx") == 'l';
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

static RCmdResult args_handler(RCmdContext *ctx) {
	ArgsState *state = ctx->handler_user;
	state->calls++;
	const size_t input_len = strlen (state->expected_input);
	state->args_ok = r_strs_empty (ctx->subcmd)
		&& !r_cmd_ctx_help (ctx) && !r_cmd_ctx_mode (ctx, "jq")
		&& !strcmp (ctx->subcmd.b, state->expected_input + strlen ("cmd"))
		&& RVecRStrs_length (&ctx->args) == state->expected_argc;
	size_t i;
	for (i = 0; state->args_ok && i < state->expected_argc; i++) {
		RStrs *arg = RVecRStrs_at (&ctx->args, i);
		state->args_ok = arg && r_strs_equals (*arg, state->expected_args[i])
			&& arg->a >= ctx->args_storage && arg->b <= ctx->args_storage + input_len;
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
	mu_assert_true (r_cmd_register (cmd, "af l", first_handler, NULL), "accept subcommand");
	mu_assert_true (r_cmd_register (cmd, "af\tl", first_handler, NULL), "accept tab-separated command");
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

static RCmdResult counted_handler(RCmdContext *ctx) {
	int *calls = ctx->handler_user;
	(*calls)++;
	return (RCmdResult) { 0 };
}

static bool test_r_cmd_alias_after_dispatch(void) {
	int calls = 0;
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "create alias console");
	RCmd *cmd = r_cmd_new (NULL);
	cmd->cons = cons;
	mu_assert_true (r_cmd_register (cmd, "alias", counted_handler, &calls), "register alias handler");
	mu_assert_eq (r_cmd_call (cmd, "alias"), 0, "dispatch before aliases exist");
	mu_assert_eq (calls, 1, "handler runs before alias creation");
	mu_assert_true (r_cmd_alias_set_raw (cmd, "alias", (const ut8 *)"value", 6, false), "create data alias");
	mu_assert_true (r_cmd_alias_set_raw (cmd, "alias", (const ut8 *)"2", 2, true), "append data alias");
	mu_assert_eq (r_cmd_call (cmd, "alias"), 1, "data alias takes precedence");
	mu_assert_eq (calls, 1, "alias skips registered handler");
	mu_assert_streq (r_cons_get_buffer (cons, NULL), "value2", "alias output is captured");
	mu_assert_true (r_cmd_alias_del (cmd, "alias"), "remove data alias");
	mu_assert_eq (r_cmd_call (cmd, "alias"), 0, "dispatch after alias removal");
	mu_assert_eq (calls, 2, "handler resumes after alias removal");
	r_cmd_free (cmd);
	r_cons_free (cons);
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
		.expected_subcmd = "fl?",
		.action = R_CMD_ACTION_CONTINUE,
		.status = 7
	};
	DispatchState child = {
		.expected_subcmd = "l?",
		.action = R_CMD_ACTION_UNHANDLED
	};
	parent.expected_user = child.expected_user = &child;
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "create borrowed console");
	RCmd *cmd = r_cmd_new (&child);
	cmd->cons = parent.expected_cons = child.expected_cons = cons;
	mu_assert_true (r_cmd_register (cmd, "a", dispatch_handler, &parent), "register parent handler");
	mu_assert_true (r_cmd_register (cmd, "af", dispatch_handler, &child), "register child handler");
	mu_assert_eq (r_cmd_call (cmd, "afl?"), 7, "parent handles child fallback");
	mu_assert_eq (child.calls, 1, "longest prefix called first");
	mu_assert_eq (parent.calls, 1, "parent prefix called after unhandled");
	mu_assert_true (child.context_ok && parent.context_ok, "handlers receive context and subcmd slice");
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

typedef struct {
	const char *expected_subcmd;
	const char *expected_arg0;
	size_t expected_argc;
	RCmdAction action;
	int calls;
	bool ok;
} MultiwordState;

static RCmdResult multiword_handler(RCmdContext *ctx) {
	MultiwordState *state = ctx->handler_user;
	state->calls++;
	const size_t argc = RVecRStrs_length (&ctx->args);
	state->ok = r_strs_equals_str (ctx->subcmd, state->expected_subcmd)
		&& argc == state->expected_argc
		&& (!state->expected_arg0
			|| (argc && r_strs_equals_str (*RVecRStrs_at (&ctx->args, 0), state->expected_arg0)));
	return (RCmdResult) { .action = state->action };
}

static bool test_r_cmd_multiword_dispatch(void) {
	MultiwordState spaced = {
		.expected_subcmd = "?",
		.expected_argc = 0,
		.action = R_CMD_ACTION_UNHANDLED
	};
	MultiwordState plain = {
		.expected_subcmd = "",
		.expected_arg0 = "l?",
		.expected_argc = 1,
		.action = R_CMD_ACTION_CONTINUE
	};
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "af l", multiword_handler, &spaced), "register spaced name");
	mu_assert_true (r_cmd_register (cmd, "af", multiword_handler, &plain), "register plain name");
	mu_assert_eq (r_cmd_call (cmd, "af l?"), 0, "fallback reaches plain handler");
	mu_assert_eq (spaced.calls, 1, "spaced handler tried first");
	mu_assert_eq (plain.calls, 1, "plain handler called on fallback");
	mu_assert_true (spaced.ok, "spaced registration excludes its name from args");
	mu_assert_true (plain.ok, "fallback reparses args from the shorter match");
	r_cmd_free (cmd);
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
	RStrs unmatched_expected[] = { R_STRS_LIT ("unterminated") };
	state.expected_input = "cmd 'unterminated";
	state.expected_args = unmatched_expected;
	state.expected_argc = R_ARRAY_SIZE (unmatched_expected);
	mu_assert_eq (r_cmd_call (cmd, state.expected_input), 0, "dispatch accepts unmatched quote");
	mu_assert_true (state.args_ok, "dispatch receives best-effort arguments");
	r_cmd_free (cmd);
	mu_end;
}

static bool test_r_core_call_context_args(void) {
	RStrs expected[] = {
		R_STRS_LIT ("say\"hi"),
		R_STRS_LIT ("single value"),
		R_STRS_LIT ("a\nb")
	};
	const char *input = "cmd say\\\"hi 'single value' a\\nb";
	ArgsState state = {
		.expected_input = input,
		.expected_args = expected,
		.expected_argc = R_ARRAY_SIZE (expected)
	};
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	mu_assert_true (r_cmd_register (core->rcmd, "cmd", args_handler, &state), "register argument handler");
	mu_assert_eq (r_core_call (core, input), 0, "direct call dispatch");
	mu_assert_true (state.args_ok, "direct call decodes quotes and escapes");
	r_core_free (core);
	mu_end;
}

typedef struct {
	RCorePluginSession *session;
	int calls;
	int legacy_calls;
	bool context_ok;
} CorePluginState;

static CorePluginState core_plugin_state;

static bool test_core_plugin_init(RCorePluginSession *cps) {
	core_plugin_state = (CorePluginState) { 0 };
	core_plugin_state.session = cps;
	cps->data = &core_plugin_state;
	return true;
}

static RCmdResult test_core_plugin_call(RCmdContext *ctx) {
	RCorePluginSession *cps = ctx->handler_user;
	CorePluginState *state = cps->data;
	state->calls++;
	state->context_ok = cps == state->session
		&& ctx->user == cps->core
		&& ctx->cmd == cps->core->rcmd
		&& ctx->cons == r_core_get_cons (cps->core)
		&& r_strs_equals_str (ctx->subcmd, "?");
	return (RCmdResult) { 0 };
}

static bool test_core_plugin_legacy_call(RCorePluginSession *cps, const char *input) {
	CorePluginState *state = cps->data;
	if (!strcmp (input, "legacyplug")) {
		state->legacy_calls++;
		return true;
	}
	return false;
}

static bool test_r_core_plugin_context_callback(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	RCorePlugin plugin = {
		.meta = {
			.name = "test-context-plugin",
			.desc = "test contextual core plugin",
			.license = "MIT",
		},
		.init = test_core_plugin_init,
		.call = test_core_plugin_legacy_call,
		.command = "ctxplug",
		.call_ctx = test_core_plugin_call,
	};
	mu_assert_true (r_core_plugin_add (core->rcmd, &plugin), "add contextual core plugin");
	mu_assert_eq (r_core_call (core, "ctxplug?"), 0, "dispatch contextual core plugin");
	mu_assert_eq (core_plugin_state.calls, 1, "context callback called once");
	mu_assert_true (core_plugin_state.context_ok, "plugin receives its session and command context");
	mu_assert_eq (r_core_call (core, "legacyplug"), 1, "legacy callback remains available");
	mu_assert_eq (core_plugin_state.legacy_calls, 1, "legacy callback called once");
	mu_assert_true (r_core_plugin_remove (core->rcmd, &plugin), "remove contextual core plugin");
	r_core_call (core, "ctxplug?");
	mu_assert_eq (core_plugin_state.calls, 1, "removed plugin is no longer dispatched");
	r_core_free (core);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_cmd_register);
	mu_run_test (test_r_cmd_unregister);
	mu_run_test (test_r_cmd_prefix_registry);
	mu_run_test (test_r_cmd_alias_after_dispatch);
	mu_run_test (test_r_cmd_registry_dispatch);
	mu_run_test (test_r_cmd_multiword_dispatch);
	mu_run_test (test_r_cmd_context_args);
	mu_run_test (test_r_core_call_context_args);
	mu_run_test (test_r_core_plugin_context_callback);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
