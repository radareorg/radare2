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

	RThread *releaser = r_th_new (release_waiting_task, &state, 0);
	mu_assert_notnull (releaser, "create task releaser");
	mu_assert_true (r_th_start (releaser), "start task releaser");

	r_core_cmdf (core, "&& %d", state.task->id);

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
	mu_assert_true (task_identity, "worker resolves its own task");
	mu_assert_true (waited, "&& waits for task completion");
	mu_assert_true (output_ready, "&& returns only after the task result is complete");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_task_join_uses_thread_identity);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
