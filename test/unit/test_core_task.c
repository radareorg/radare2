#include <r_core.h>
#include "minunit.h"

typedef struct {
	RCoreTaskScheduler *scheduler;
	RCoreTask *task;
	RThreadLock *lock;
	RThreadCond *cond;
	bool started;
	bool release;
	bool abort;
	bool waiting;
	bool task_identity;
} TaskWaitState;

static void task_started(REvent *ev, int type, void *user, void *data) {
	(void)ev;
	(void)type;
	TaskWaitState *state = user;
	if (data != state->task) {
		return;
	}
	r_th_lock_enter (state->lock);
	state->task_identity = r_core_task_self (state->scheduler) == state->task;
	state->started = true;
	r_th_cond_signal_all (state->cond);
	while (!state->release) {
		r_th_cond_wait (state->cond, state->lock, 0);
	}
	r_th_lock_leave (state->lock);
}

static RThreadFunctionRet release_waiting_task(RThread *th) {
	TaskWaitState *state = th->user;
	for (;;) {
		r_th_lock_enter (state->scheduler->lock);
		bool waiting = state->scheduler->main_task->state == R_CORE_TASK_STATE_SLEEPING;
		r_th_lock_leave (state->scheduler->lock);

		r_th_lock_enter (state->lock);
		if (waiting) {
			state->waiting = true;
			state->release = true;
			r_th_cond_signal_all (state->cond);
			r_th_lock_leave (state->lock);
			break;
		}
		if (state->abort) {
			r_th_lock_leave (state->lock);
			break;
		}
		r_th_lock_leave (state->lock);
		r_sys_usleep (100);
	}
	return R_TH_STOP;
}

bool test_task_join_uses_thread_identity(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");

	TaskWaitState state = {
		.scheduler = &core->tasks,
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new ()
	};
	mu_assert_notnull (state.lock, "create test lock");
	mu_assert_notnull (state.cond, "create test condition");
	mu_assert_true (r_event_hook (core->ev, R_EVENT_CORE_TASK_STARTED, task_started, &state), "hook task start");

	state.task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "?e ready", NULL, NULL);
	mu_assert_notnull (state.task, "create task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, state.task), state.task->id, "start background task");

	r_th_lock_enter (state.lock);
	while (!state.started) {
		r_th_cond_wait (state.cond, state.lock, 0);
	}
	r_th_lock_leave (state.lock);

	// the background task is running at this point, so the main thread must
	// still resolve to the main task instead of picking up the worker's identity
	bool main_identity = r_core_task_ismain (&core->tasks);
	bool child_console = state.task->cons && state.task->cons != core->cons
		&& state.task->cons->context != core->cons->context;

	RThread *releaser = r_th_new (release_waiting_task, &state, 0);
	mu_assert_notnull (releaser, "create task releaser");
	mu_assert_true (r_th_start (releaser), "start task releaser");

	r_core_cmdf (core, "&& %d", state.task->id);
	bool result_ready = state.task->res != NULL;

	r_th_lock_enter (state.lock);
	bool waited = state.waiting;
	state.abort = true;
	state.release = true;
	r_th_cond_signal_all (state.cond);
	r_th_lock_leave (state.lock);

	r_th_wait (releaser);
	r_th_free (releaser);
	r_core_task_join (&core->tasks, core->tasks.main_task, state.task->id);
	r_event_unhook (core->ev, R_EVENT_CORE_TASK_STARTED, task_started);

	bool task_identity = state.task_identity;
	bool output_ready = state.task->res && !strcmp (state.task->res, "ready\n");
	r_core_free (core);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);

	mu_assert_true (main_identity, "main ignores shared scheduler task identity");
	mu_assert_true (child_console, "capturing task owns a child console");
	mu_assert_true (task_identity, "worker resolves its own task");
	mu_assert_true (waited, "&& waits for task completion");
	mu_assert_true (result_ready, "&& returns after the task result is ready");
	mu_assert_true (output_ready, "&& returns only after the task result is complete");
	mu_end;
}

typedef struct {
	RThreadLock *lock;
	RThreadCond *cond;
	RCons *cons;
	const char *output;
	bool entered;
	bool release;
	bool broken;
	bool unhandled;
} TaskContextState;

static RCmdResult task_context_handler(RCmdContext *ctx) {
	TaskContextState *state = ctx->handler_user;
	r_th_lock_enter (state->lock);
	state->cons = ctx->cons;
	state->cons->context->color_mode = COLOR_MODE_16;
	state->entered = true;
	r_th_cond_signal_all (state->cond);
	while (!state->release) {
		r_th_cond_wait (state->cond, state->lock, 0);
	}
	state->broken = state->cons->context->breaked;
	r_th_lock_leave (state->lock);
	if (!state->broken && state->output) {
		r_cons_print (ctx->cons, state->output);
	}
	return (RCmdResult) {
		.action = state->unhandled? R_CMD_ACTION_UNHANDLED: R_CMD_ACTION_CONTINUE
	};
}

static void task_context_wait(TaskContextState *state) {
	r_th_lock_enter (state->lock);
	while (!state->entered) {
		r_th_cond_wait (state->cond, state->lock, 0);
	}
	r_th_lock_leave (state->lock);
}

static void task_context_release(TaskContextState *state) {
	r_th_lock_enter (state->lock);
	state->release = true;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
}

typedef struct {
	RThreadLock *lock;
	RThreadCond *cond;
	ut32 before;
	ut32 after;
	ut32 nested;
	bool entered;
	bool release;
} BlockSizeContextState;

static RCmdResult blocksize_child_handler(RCmdContext *ctx) {
	BlockSizeContextState *state = ctx->handler_user;
	state->nested = ctx->blocksize;
	return (RCmdResult) { 0 };
}

static RCmdResult blocksize_parent_handler(RCmdContext *ctx) {
	BlockSizeContextState *state = ctx->handler_user;
	r_th_lock_enter (state->lock);
	state->before = ctx->blocksize;
	state->entered = true;
	r_th_cond_signal_all (state->cond);
	while (!state->release) {
		r_th_cond_wait (state->cond, state->lock, 0);
	}
	r_th_lock_leave (state->lock);
	state->after = r_core_block_size_get (ctx->user);
	r_core_call (ctx->user, "blocksizechild");
	return (RCmdResult) { 0 };
}

static void blocksize_context_wait(BlockSizeContextState *state) {
	r_th_lock_enter (state->lock);
	while (!state->entered) {
		r_th_cond_wait (state->cond, state->lock, 0);
	}
	r_th_lock_leave (state->lock);
}

static void blocksize_context_release(BlockSizeContextState *state) {
	r_th_lock_enter (state->lock);
	state->release = true;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
}

bool test_task_context_blocksize_snapshot(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	const ut32 initial = r_core_block_size_get (core);
	BlockSizeContextState state = {
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new ()
	};
	mu_assert_true (r_cmd_register (core->rcmd, "blocksizeparent", blocksize_parent_handler, &state), "register parent block size command");
	mu_assert_true (r_cmd_register (core->rcmd, "blocksizechild", blocksize_child_handler, &state), "register child block size command");
	RCoreTask *task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "blocksizeparent", NULL, NULL);
	mu_assert_notnull (task, "create block size task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, task), task->id, "run block size task");
	blocksize_context_wait (&state);

	const ut32 changed = initial + 32;
	bool resized = r_core_block_size (core, changed);
	bool global_changed = r_core_block_size_get (core) == changed;
	blocksize_context_release (&state);
	r_core_task_join (&core->tasks, core->tasks.main_task, task->id);

	bool snapshot_stable = state.before == initial && state.after == initial;
	bool nested_inherited = state.nested == initial;
	state.nested = 0;
	r_core_call (core, "blocksizechild");
	bool new_root_changed = state.nested == changed;
	char *output = r_core_cmd_str (core, "b 96;b+4;b");
	bool explicit_update = output && !strcmp (output, "0x64\n");
	free (output);
	r_cmd_unregister (core->rcmd, "blocksizeparent");
	r_cmd_unregister (core->rcmd, "blocksizechild");
	r_core_free (core);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);

	mu_assert_true (resized, "resize shared block size");
	mu_assert_true (global_changed, "new roots observe changed block size");
	mu_assert_true (snapshot_stable, "running command keeps its block size snapshot");
	mu_assert_true (nested_inherited, "nested command inherits the parent block size");
	mu_assert_true (new_root_changed, "later root snapshots the changed block size");
	mu_assert_true (explicit_update, "explicit b updates the current command context");
	mu_end;
}

bool test_task_context_console_isolation(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	r_cons_reset (core->cons);
	const int parent_color = core->cons->context->color_mode;
	TaskContextState state = {
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new (),
		.output = "task-only"
	};
	mu_assert_true (r_cmd_register (core->rcmd, "taskctx", task_context_handler, &state), "register context command");
	RCoreTask *task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "taskctx;?e legacy", NULL, NULL);
	mu_assert_notnull (task, "create context task");
	mu_assert_notnull (task->cons, "task child console");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, task), task->id, "run context task");
	task_context_wait (&state);

	r_cons_print (core->cons, "main-only");
	task_context_release (&state);
	r_core_task_join (&core->tasks, core->tasks.main_task, task->id);

	size_t parent_size;
	const char *parent_output = r_cons_get_buffer (core->cons, &parent_size);
	bool context_console = state.cons == task->cons && task->cons != core->cons;
	bool context_isolation = task->cons->context != core->cons->context
		&& core->cons->context->color_mode == parent_color;
	bool main_output = parent_size == strlen ("main-only")
		&& !memcmp (parent_output, "main-only", parent_size);
	bool task_output = task->res && !strcmp (task->res, "task-onlylegacy\n");
	bool child_drained = !r_cons_get_buffer (task->cons, NULL);
	state.cons = NULL;
	state.output = NULL;
	state.entered = false;
	state.release = true;
	RCoreTask *empty_task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "taskctx?", NULL, NULL);
	mu_assert_notnull (empty_task, "create empty-output task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, empty_task), empty_task->id, "run empty-output task");
	r_core_task_join (&core->tasks, core->tasks.main_task, empty_task->id);
	bool empty_output = empty_task->res && !*empty_task->res;
	bool suffix_context = state.cons == empty_task->cons;
	state.output = "context-only";
	state.unhandled = false;
	r_cmd_unregister (core->rcmd, "?e");
	mu_assert_true (r_cmd_register (core->rcmd, "?e", task_context_handler, &state), "register replacement command");
	RCoreTask *replacement_task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "?e ignored", NULL, NULL);
	mu_assert_notnull (replacement_task, "create replacement task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, replacement_task), replacement_task->id, "run replacement task");
	r_core_task_join (&core->tasks, core->tasks.main_task, replacement_task->id);
	bool replacement_output = replacement_task->res && !strcmp (replacement_task->res, "context-only");
	r_cmd_unregister (core->rcmd, "?e");
	r_cmd_unregister (core->rcmd, "taskctx");
	r_core_free (core);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);

	mu_assert_true (context_console, "new handler receives task console");
	mu_assert_true (context_isolation, "task context settings stay isolated");
	mu_assert_true (main_output, "main output remains in parent console");
	mu_assert_true (task_output, "task result drains child output");
	mu_assert_true (child_drained, "task console is empty after draining");
	mu_assert_true (empty_output, "empty task output remains valid");
	mu_assert_true (suffix_context, "registered suffix uses the task console");
	mu_assert_true (replacement_output, "registered replacement handles output without legacy fallback");
	mu_end;
}

bool test_task_cancel_breaks_child_console(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	r_cons_break_clear (core->cons);
	TaskContextState state = {
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new ()
	};
	mu_assert_true (r_cmd_register (core->rcmd, "taskctx", task_context_handler, &state), "register context command");
	RCoreTask *task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "taskctx", NULL, NULL);
	mu_assert_notnull (task, "create cancellable task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, task), task->id, "run cancellable task");
	task_context_wait (&state);

	bool canceled = r_core_task_cancel (task, false);
	bool parent_ok = !core->cons->context->breaked;
	task_context_release (&state);
	r_core_task_join (&core->tasks, core->tasks.main_task, task->id);

	bool child_broken = state.broken && task->cons->context->breaked;
	bool empty_output = task->res && !*task->res;
	r_cmd_unregister (core->rcmd, "taskctx");
	r_core_free (core);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);

	mu_assert_true (canceled, "cancel task through child console");
	mu_assert_true (parent_ok, "cancel leaves parent console unbroken");
	mu_assert_true (child_broken, "cancel breaks task console");
	mu_assert_true (empty_output, "empty task output remains valid");
	mu_end;
}

bool test_registered_echo_nested_task(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	RCoreTask *nested = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true,
		"echo $(echo nested); echo loose; echo second", NULL, NULL);
	RCoreTask *other = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true,
		"echo other", NULL, NULL);
	RCoreTask *mixed = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true,
		"echo mixed; ?v 42", NULL, NULL);
	mu_assert_notnull (nested, "create nested echo task");
	mu_assert_notnull (other, "create other echo task");
	mu_assert_notnull (mixed, "create mixed task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, nested), nested->id, "run nested echo task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, other), other->id, "run other echo task");
	r_core_task_join (&core->tasks, core->tasks.main_task, nested->id);
	r_core_task_join (&core->tasks, core->tasks.main_task, other->id);
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, mixed), mixed->id, "run mixed task");
	r_core_task_join (&core->tasks, core->tasks.main_task, mixed->id);

	bool nested_ok = nested->res && !strcmp (nested->res, "nested\nloose\nsecond\n");
	bool other_ok = other->res && !strcmp (other->res, "other\n");
	bool mixed_ok = mixed->res && !strcmp (mixed->res, "mixed\n0x2a\n");
	bool children_drained = !r_cons_get_buffer (nested->cons, NULL)
		&& !r_cons_get_buffer (other->cons, NULL);
	r_core_free (core);
	mu_assert_true (nested_ok, "nested echo output stays in its task context");
	mu_assert_true (other_ok, "parallel echo output stays in its task context");
	mu_assert_true (mixed_ok, "mixed commands stay on the legacy capture path");
	mu_assert_true (children_drained, "task consoles are drained");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_task_join_uses_thread_identity);
	mu_run_test (test_task_context_blocksize_snapshot);
	mu_run_test (test_task_context_console_isolation);
	mu_run_test (test_task_cancel_breaks_child_console);
	mu_run_test (test_registered_echo_nested_task);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
