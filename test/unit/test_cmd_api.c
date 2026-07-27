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
	bool expected_verbatim;
	int calls;
	bool args_ok;
} ArgsState;

static RCmdResult args_handler(RCmdContext *ctx) {
	ArgsState *state = ctx->handler_user;
	state->calls++;
	const size_t input_len = strlen (state->expected_input);
	state->args_ok = r_strs_empty (ctx->subcmd)
		&& !r_cmd_ctx_help (ctx) && !r_cmd_ctx_mode (ctx, "jq")
		&& ctx->verbatim == state->expected_verbatim
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
	mu_assert_eq (r_cmd_alias_set_str (cmd, "alias", "value"), 1, "create data alias");
	mu_assert_eq (r_cmd_call (cmd, "alias"), 1, "data alias takes precedence");
	mu_assert_eq (calls, 1, "alias skips pinned handler");
	mu_assert_streq (r_cons_get_buffer (cons, NULL), "value", "alias output is captured");
	mu_assert_true (r_cmd_alias_del (cmd, "alias"), "remove data alias");
	mu_assert_eq (r_cmd_call (cmd, "alias"), 0, "dispatch after alias removal");
	mu_assert_eq (calls, 2, "handler resumes after alias removal");
	r_cmd_free (cmd);
	r_cons_free (cons);
	mu_end;
}

static RCmdResult unregister_self_handler(RCmdContext *ctx) {
	bool *unregistered = ctx->handler_user;
	*unregistered = r_cmd_unregister (ctx->cmd, "self");
	return (RCmdResult) { 0 };
}

static bool test_r_cmd_unregister_self(void) {
	bool unregistered = true;
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "self", unregister_self_handler, &unregistered), "register self handler");
	r_log_init ();
	const RLogLevel level = r_log_get_level ();
	r_log_set_level (R_LOG_LEVEL_FATAL);
	const int result = r_cmd_call (cmd, "self");
	r_log_set_level (level);
	mu_assert_eq (result, 0, "self-unregistering callback returns");
	mu_assert_false (unregistered, "self-unregistration is rejected");
	mu_assert_true (r_cmd_unregister (cmd, "self"), "external unregistration still succeeds");
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

typedef struct {
	RCmd *cmd;
	size_t removed;
} ForeachMutation;

static bool unregister_visited_command(RStrs name, void *user) {
	ForeachMutation *mutation = user;
	char *command = r_strs_tostring (name);
	const bool removed = command && r_cmd_unregister (mutation->cmd, command);
	free (command);
	if (removed) {
		mutation->removed++;
	}
	return removed;
}

static bool test_r_cmd_foreach_mutation(void) {
	RCmd *cmd = r_cmd_new (NULL);
	mu_assert_true (r_cmd_register (cmd, "af", first_handler, NULL), "register af");
	mu_assert_true (r_cmd_register (cmd, "afl", first_handler, NULL), "register afl");
	mu_assert_true (r_cmd_register (cmd, "aflj", first_handler, NULL), "register aflj");
	ForeachMutation mutation = {
		.cmd = cmd
	};
	mu_assert_true (r_cmd_foreach_prefix (cmd, "af", unregister_visited_command, &mutation), "mutate registry from snapshot visitor");
	mu_assert_eq (mutation.removed, 3, "visitor sees the entry snapshot");
	mu_assert_eq (r_trie_size (cmd->handlers), 0, "visitor removes every snapshotted handler");
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
	RStrs raw_expected[] = { R_STRS_LIT ("unterminated") };
	state.expected_input = "cmd 'unterminated";
	state.expected_args = raw_expected;
	state.expected_argc = R_ARRAY_SIZE (raw_expected);
	mu_assert_eq (r_cmd_call (cmd, state.expected_input), 0, "raw dispatch accepts unmatched quote");
	mu_assert_true (state.args_ok, "raw dispatch receives best-effort metadata");
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
	mu_assert_true (state.args_ok, "direct call uses shared argument decoding");
	r_core_free (core);
	mu_end;
}

typedef struct {
	RCmd *cmd;
	RThreadLock *lock;
	RThreadCond *cond;
	size_t calls;
	int workers;
	bool stop;
	bool failed;
} ConcurrentRegistryState;

static RCmdResult concurrent_registry_handler(RCmdContext *ctx) {
	ConcurrentRegistryState *state = ctx->handler_user;
	r_th_lock_enter (state->lock);
	state->calls++;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
	return (RCmdResult) { 0 };
}

static RThreadFunctionRet concurrent_registry_dispatch(RThread *thread) {
	ConcurrentRegistryState *state = thread->user;
	r_th_lock_enter (state->lock);
	state->workers++;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
	while (true) {
		r_th_lock_enter (state->lock);
		const bool stop = state->stop;
		r_th_lock_leave (state->lock);
		if (stop) {
			break;
		}
		const int result = r_cmd_call (state->cmd, "race");
		if (result != 0 && result != -1) {
			r_th_lock_enter (state->lock);
			state->failed = true;
			r_th_lock_leave (state->lock);
		}
	}
	return R_TH_STOP;
}

static bool test_r_cmd_concurrent_registry(void) {
	ConcurrentRegistryState state = {
		.cmd = r_cmd_new (NULL),
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new ()
	};
	mu_assert_true (r_cmd_register (state.cmd, "race", concurrent_registry_handler, &state), "register concurrent handler");
	RThread *workers[2] = {
		r_th_new (concurrent_registry_dispatch, &state, 0),
		r_th_new (concurrent_registry_dispatch, &state, 0)
	};
	mu_assert_notnull (workers[0], "create first dispatch thread");
	mu_assert_notnull (workers[1], "create second dispatch thread");
	mu_assert_true (r_th_start (workers[0]), "start first dispatch thread");
	mu_assert_true (r_th_start (workers[1]), "start second dispatch thread");
	r_th_lock_enter (state.lock);
	while (state.workers < 2 || !state.calls) {
		r_th_cond_wait (state.cond, state.lock);
	}
	r_th_lock_leave (state.lock);
	bool mutations_ok = true;
	size_t i;
	for (i = 0; i < 2000; i++) {
		if (!r_cmd_unregister (state.cmd, "race")
			|| !r_cmd_register (state.cmd, "race", concurrent_registry_handler, &state)
			|| !r_cmd_alias_set_cmd (state.cmd, "race", "noop")
			|| !r_cmd_alias_del (state.cmd, "race")) {
			mutations_ok = false;
			break;
		}
		if (!(i % 64)) {
			r_sys_usleep (10);
		}
	}
	r_th_lock_enter (state.lock);
	state.stop = true;
	r_th_lock_leave (state.lock);
	r_th_wait (workers[0]);
	r_th_wait (workers[1]);
	r_th_free (workers[0]);
	r_th_free (workers[1]);
	r_th_lock_enter (state.lock);
	const bool dispatched = state.calls > 0 && !state.failed;
	r_th_lock_leave (state.lock);
	r_cmd_unregister (state.cmd, "race");
	r_cmd_free (state.cmd);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);
	mu_assert_true (mutations_ok, "concurrent registry mutations succeed");
	mu_assert_true (dispatched, "concurrent dispatch results stay valid");
	mu_end;
}

typedef struct {
	RCmd *cmd;
	RThreadLock *lock;
	RThreadCond *cond;
	bool entered;
	bool release;
	bool exited;
	bool unregistered;
	int dispatch_result;
	int replacement_calls;
} RegistryBarrierState;

static RCmdResult registry_barrier_handler(RCmdContext *ctx) {
	RegistryBarrierState *state = ctx->handler_user;
	r_th_lock_enter (state->lock);
	state->entered = true;
	r_th_cond_signal_all (state->cond);
	while (!state->release) {
		r_th_cond_wait (state->cond, state->lock);
	}
	state->exited = true;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
	return (RCmdResult) { 0 };
}

static RCmdResult registry_replacement_handler(RCmdContext *ctx) {
	RegistryBarrierState *state = ctx->handler_user;
	state->replacement_calls++;
	return (RCmdResult) { 0 };
}

static RThreadFunctionRet registry_barrier_dispatch(RThread *thread) {
	RegistryBarrierState *state = thread->user;
	state->dispatch_result = r_cmd_call (state->cmd, "barrier");
	return R_TH_STOP;
}

static RThreadFunctionRet registry_barrier_unregister(RThread *thread) {
	RegistryBarrierState *state = thread->user;
	const bool unregistered = r_cmd_unregister (state->cmd, "barrier");
	r_th_lock_enter (state->lock);
	state->unregistered = unregistered;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
	return R_TH_STOP;
}

static bool test_r_cmd_unregister_barrier(void) {
	RegistryBarrierState state = {
		.cmd = r_cmd_new (NULL),
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new (),
		.dispatch_result = -1
	};
	mu_assert_true (r_cmd_register (state.cmd, "barrier", registry_barrier_handler, &state), "register blocking handler");
	mu_assert_true (r_cmd_register (state.cmd, "unrelated", first_handler, NULL), "register unrelated handler");
	RThread *dispatch = r_th_new (registry_barrier_dispatch, &state, 0);
	RThread *unregister = r_th_new (registry_barrier_unregister, &state, 0);
	mu_assert_notnull (dispatch, "create dispatch thread");
	mu_assert_notnull (unregister, "create unregister thread");
	mu_assert_true (r_th_start (dispatch), "start dispatch thread");
	r_th_lock_enter (state.lock);
	while (!state.entered) {
		r_th_cond_wait (state.cond, state.lock);
	}
	r_th_lock_leave (state.lock);
	const bool unrelated_removed = r_cmd_unregister (state.cmd, "unrelated");
	mu_assert_true (r_th_start (unregister), "start unregister thread");
	bool replacement_registered = false;
	size_t i;
	for (i = 0; i < 10000 && !replacement_registered; i++) {
		replacement_registered = r_cmd_register (state.cmd, "barrier", registry_replacement_handler, &state);
		if (!replacement_registered) {
			r_sys_usleep (10);
		}
	}
	const int replacement_result = replacement_registered? r_cmd_call (state.cmd, "barrier"): -1;
	r_th_lock_enter (state.lock);
	const bool unregister_waited = !state.unregistered;
	state.release = true;
	r_th_cond_signal_all (state.cond);
	r_th_lock_leave (state.lock);
	r_th_wait (dispatch);
	r_th_wait (unregister);
	r_th_free (dispatch);
	r_th_free (unregister);
	const bool old_call_finished = state.exited && state.unregistered && state.dispatch_result == 0;
	r_cmd_unregister (state.cmd, "barrier");
	r_cmd_free (state.cmd);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);
	mu_assert_true (replacement_registered, "replacement registers while old callback is pinned");
	mu_assert_eq (replacement_result, 0, "replacement dispatches while unregister waits");
	mu_assert_eq (state.replacement_calls, 1, "replacement handler runs once");
	mu_assert_true (unrelated_removed, "another thread unregisters an unrelated handler");
	mu_assert_true (unregister_waited, "unregister waits for the old callback");
	mu_assert_true (old_call_finished, "unregister returns after the old callback exits");
	mu_end;
}

typedef struct {
	RCmd *cmd;
	RThreadLock *lock;
	RThreadCond *cond;
	bool entered;
	bool release;
	bool free_started;
	bool free_finished;
	int dispatch_result;
} RegistryFreeState;

static RCmdResult registry_free_handler(RCmdContext *ctx) {
	(void)ctx;
	return (RCmdResult) { .action = R_CMD_ACTION_UNHANDLED };
}

static int registry_free_legacy(void *user, const char *input) {
	RegistryFreeState *state = user;
	r_th_lock_enter (state->lock);
	state->entered = true;
	r_th_cond_signal_all (state->cond);
	while (!state->release) {
		r_th_cond_wait (state->cond, state->lock);
	}
	r_th_lock_leave (state->lock);
	return !strcmp (input, "reebarrier")? 0: -1;
}

static RThreadFunctionRet registry_free_dispatch(RThread *thread) {
	RegistryFreeState *state = thread->user;
	state->dispatch_result = r_cmd_call (state->cmd, "freebarrier");
	return R_TH_STOP;
}

static RThreadFunctionRet registry_free_registry(RThread *thread) {
	RegistryFreeState *state = thread->user;
	r_th_lock_enter (state->lock);
	state->free_started = true;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
	r_cmd_free (state->cmd);
	r_th_lock_enter (state->lock);
	state->free_finished = true;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
	return R_TH_STOP;
}

static bool test_r_cmd_free_barrier(void) {
	RegistryFreeState state = {
		.cmd = r_cmd_new (NULL),
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new (),
		.dispatch_result = -1
	};
	r_cmd_set_data (state.cmd, &state);
	mu_assert_true (r_cmd_register (state.cmd, "freebarrier", registry_free_handler, &state), "register free barrier");
	mu_assert_true (r_cmd_add (state.cmd, "f", registry_free_legacy), "register legacy free barrier");
	RThread *dispatch = r_th_new (registry_free_dispatch, &state, 0);
	RThread *free_thread = r_th_new (registry_free_registry, &state, 0);
	mu_assert_notnull (dispatch, "create free barrier dispatch thread");
	mu_assert_notnull (free_thread, "create registry free thread");
	mu_assert_true (r_th_start (dispatch), "start free barrier dispatch");
	r_th_lock_enter (state.lock);
	while (!state.entered) {
		r_th_cond_wait (state.cond, state.lock);
	}
	r_th_lock_leave (state.lock);
	mu_assert_true (r_th_start (free_thread), "start registry free");
	r_th_lock_enter (state.lock);
	while (!state.free_started) {
		r_th_cond_wait (state.cond, state.lock);
	}
	r_th_lock_leave (state.lock);
	while (r_cmd_register (state.cmd, "late", first_handler, NULL)) {
		r_cmd_unregister (state.cmd, "late");
	}
	r_th_lock_enter (state.lock);
	const bool free_waited = !state.free_finished;
	state.release = true;
	r_th_cond_signal_all (state.cond);
	r_th_lock_leave (state.lock);
	r_th_wait (dispatch);
	r_th_wait (free_thread);
	r_th_free (dispatch);
	r_th_free (free_thread);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);
	mu_assert_true (free_waited, "free waits for active dispatch");
	mu_assert_eq (state.dispatch_result, 0, "dispatch finishes before registry free");
	mu_assert_true (state.free_finished, "registry free finishes after dispatch");
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_cmd_register);
	mu_run_test (test_r_cmd_unregister);
	mu_run_test (test_r_cmd_alias_after_dispatch);
	mu_run_test (test_r_cmd_unregister_self);
	mu_run_test (test_r_cmd_prefix_registry);
	mu_run_test (test_r_cmd_foreach_mutation);
	mu_run_test (test_r_cmd_registry_dispatch);
	mu_run_test (test_r_cmd_multiword_dispatch);
	mu_run_test (test_r_cmd_context_args);
	mu_run_test (test_r_core_call_context_args);
	mu_run_test (test_r_cmd_concurrent_registry);
	mu_run_test (test_r_cmd_unregister_barrier);
	mu_run_test (test_r_cmd_free_barrier);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
