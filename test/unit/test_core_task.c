#include <r_core.h>
#include "minunit.h"

typedef struct {
	RCoreTaskScheduler *scheduler;
	RCoreTaskScheduler *other_scheduler;
	RCoreTask *task;
	RThreadLock *lock;
	RThreadCond *cond;
	bool started;
	bool release;
	bool abort;
	bool waiting;
	bool task_identity;
	bool other_identity;
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
	state->other_identity = r_core_task_self (state->other_scheduler) == state->other_scheduler->main_task;
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
	}
	return R_TH_STOP;
}

bool test_task_join_uses_thread_identity(void) {
	RCore *core = r_core_new ();
	RCore *other_core = r_core_new ();
	mu_assert_notnull (core, "create core");
	mu_assert_notnull (other_core, "create second core");

	TaskWaitState state = {
		.scheduler = &core->tasks,
		.other_scheduler = &other_core->tasks,
		.lock = r_th_lock_new (false),
		.cond = r_th_cond_new ()
	};
	mu_assert_notnull (state.lock, "create test lock");
	mu_assert_notnull (state.cond, "create test condition");
	mu_assert_true (r_event_hook (core->ev, R_EVENT_CORE_TASK_STARTED, task_started, &state), "hook task start");

	state.task = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, "?e ready", NULL, NULL);
	mu_assert_notnull (state.task, "create task");
	mu_assert_eq (state.task->id, 1, "first background task id");
	mu_assert_eq (r_core_task_run_threaded (&core->tasks, state.task), 1, "start background task");

	r_th_lock_enter (state.lock);
	while (!state.started) {
		r_th_cond_wait (state.cond, state.lock);
	}
	r_th_lock_leave (state.lock);

	r_th_lock_enter (core->tasks.lock);
	core->tasks.current_task = state.task;
	r_th_lock_leave (core->tasks.lock);
	bool main_identity = r_core_task_self (&core->tasks) == core->tasks.main_task;

	RThread *releaser = r_th_new (release_waiting_task, &state, 0);
	mu_assert_notnull (releaser, "create task releaser");
	mu_assert_true (r_th_start (releaser), "start task releaser");

	r_core_cmd0 (core, "&& 1");

	r_th_lock_enter (state.lock);
	bool waited = state.waiting;
	bool result_ready = state.task->res != NULL;
	state.abort = true;
	state.release = true;
	r_th_cond_signal_all (state.cond);
	r_th_lock_leave (state.lock);

	r_th_wait (releaser);
	r_th_free (releaser);
	r_core_task_join (&core->tasks, core->tasks.main_task, state.task->id);
	r_event_unhook (core->ev, R_EVENT_CORE_TASK_STARTED, task_started);
	r_th_lock_enter (core->tasks.lock);
	core->tasks.current_task = NULL;
	r_th_lock_leave (core->tasks.lock);

	bool task_identity = state.task_identity;
	bool other_identity = state.other_identity;
	bool output_ready = state.task->res && !strcmp (state.task->res, "ready\n");
	r_core_free (other_core);
	r_core_free (core);
	r_th_cond_free (state.cond);
	r_th_lock_free (state.lock);

	mu_assert_true (main_identity, "main ignores shared scheduler task identity");
	mu_assert_true (task_identity, "worker resolves its own task");
	mu_assert_true (other_identity, "task identity does not leak across cores");
	mu_assert_true (waited, "&& waits for task completion");
	mu_assert_true (result_ready, "&& returns only after task result is ready");
	mu_assert_true (output_ready, "task result is complete");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_task_join_uses_thread_identity);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
