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
		r_th_cond_wait (state->cond, state->lock);
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
		r_th_cond_wait (state.cond, state.lock);
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
} TaskContextState;

static RCmdResult task_context_handler(RCmdContext *ctx) {
	TaskContextState *state = ctx->handler_user;
	r_th_lock_enter (state->lock);
	state->cons = ctx->cons;
	state->cons->context->color_mode = COLOR_MODE_16;
	state->entered = true;
	r_th_cond_signal_all (state->cond);
	while (!state->release) {
		r_th_cond_wait (state->cond, state->lock);
	}
	state->broken = state->cons->context->breaked;
	r_th_lock_leave (state->lock);
	if (!state->broken && state->output) {
		r_cons_print (ctx->cons, state->output);
	}
	return (RCmdResult) { 0 };
}

static void task_context_wait(TaskContextState *state) {
	r_th_lock_enter (state->lock);
	while (!state->entered) {
		r_th_cond_wait (state->cond, state->lock);
	}
	r_th_lock_leave (state->lock);
}

static void task_context_release(TaskContextState *state) {
	r_th_lock_enter (state->lock);
	state->release = true;
	r_th_cond_signal_all (state->cond);
	r_th_lock_leave (state->lock);
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
	RCoreTask *task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "taskctx", NULL, NULL);
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
	bool task_output = task->res && !strcmp (task->res, "task-only");
	bool child_drained = !r_cons_get_buffer (task->cons, NULL);
	state.cons = NULL;
	state.output = NULL;
	state.entered = false;
	state.release = true;
	RCoreTask *empty_task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "taskctx", NULL, NULL);
	mu_assert_notnull (empty_task, "create empty-output task");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, empty_task), empty_task->id, "run empty-output task");
	r_core_task_join (&core->tasks, core->tasks.main_task, empty_task->id);
	bool empty_output = empty_task->res && !*empty_task->res;
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

int all_tests(void) {
	mu_run_test (test_task_join_uses_thread_identity);
	mu_run_test (test_task_context_console_isolation);
	mu_run_test (test_task_cancel_breaks_child_console);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
