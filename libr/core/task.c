/* radare - LGPL - Copyright 2014-2025 - pancake */

#include <r_core.h>

// Per-thread current task pointer (TLS)
static R_TH_LOCAL RCoreTask *task_tls_current = NULL;

#define CUSTOMCORE 0

static RCore *mycore_new(RCore *core) {
#if CUSTOMCORE
	RCore *c = R_NEW (RCore);
	memcpy (c, core, sizeof (RCore));
	c->cons = r_cons_new ();
	// XXX: RConsBind must disappear. its used in bin, fs and search
	// TODO: use r_cons_clone instead
	return c;
#else
	return core;
#endif
}

static void mycore_free(RCore *a) {
#if CUSTOMCORE
	r_cons_free (a->cons);
#endif
}

R_API void r_core_task_scheduler_init(RCoreTaskScheduler *tasks, RCore *core) {
	tasks->task_id_next = 0;
	tasks->tasks = r_list_newf ( (RListFree)r_core_task_decref);
	tasks->tasks_queue = r_list_new ();
	tasks->oneshot_queue = r_list_newf (free);
	tasks->oneshots_enqueued = 0;
	tasks->lock = r_th_lock_new (true);
	tasks->tasks_running = 0;
	tasks->oneshot_running = false;
	tasks->main_task = r_core_task_new (core, false, NULL, NULL, NULL);
	r_list_append (tasks->tasks, tasks->main_task);
	tasks->current_task = NULL;
}

R_API void r_core_task_scheduler_fini(RCoreTaskScheduler *tasks) {
	// Join all task threads before freeing lists to avoid races
	RListIter *iter;
	RCoreTask *t;
	r_th_lock_enter (tasks->lock);
	RList *snapshot = r_list_clone (tasks->tasks, NULL);
	r_th_lock_leave (tasks->lock);
	if (snapshot) {
		r_list_foreach (snapshot, iter, t) {
			if (t && t->thread) {
				r_th_wait (t->thread);
			}
		}
		r_list_free (snapshot);
	}
	r_list_free (tasks->tasks);
	r_list_free (tasks->tasks_queue);
	r_list_free (tasks->oneshot_queue);
	r_th_lock_free (tasks->lock);
}

#if HAVE_PTHREAD
#define TASK_SIGSET_T sigset_t
static void tasks_lock_block_signals(sigset_t *old_sigset) {
	sigset_t block_sigset;
	sigemptyset (&block_sigset);
	sigaddset (&block_sigset, SIGWINCH);
	r_signal_sigmask (SIG_BLOCK, &block_sigset, old_sigset);
}

static void tasks_lock_block_signals_reset(sigset_t *old_sigset) {
	r_signal_sigmask (SIG_SETMASK, old_sigset, NULL);
}
#else
#define TASK_SIGSET_T void *
static void tasks_lock_block_signals(TASK_SIGSET_T *old_sigset) {(void)old_sigset; }
static void tasks_lock_block_signals_reset(TASK_SIGSET_T *old_sigset) {(void)old_sigset; }
#endif

static void tasks_lock_enter(RCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	tasks_lock_block_signals (old_sigset);
	r_th_lock_enter (scheduler->lock);
}

static void tasks_lock_leave(RCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	r_th_lock_leave (scheduler->lock);
	tasks_lock_block_signals_reset (old_sigset);
}

typedef struct oneshot_t {
	RCoreTaskOneShot func;
	void *user;
} OneShot;

R_API void r_core_task_print(RCore *core, RCoreTask *task, PJ *pj, int mode) {
	switch (mode) {
	case 'j': {
		pj_o (pj);
		pj_ki (pj, "id", task->id);
		pj_k (pj, "state");
		switch (task->state) {
		case R_CORE_TASK_STATE_BEFORE_START:
			pj_s (pj, "before_start");
			break;
		case R_CORE_TASK_STATE_RUNNING:
			pj_s (pj, "running");
			break;
		case R_CORE_TASK_STATE_SLEEPING:
			pj_s (pj, "sleeping");
			break;
		case R_CORE_TASK_STATE_DONE:
			pj_s (pj, "done");
			break;
		}
		pj_kb (pj, "transient", task->transient);
		pj_ks (pj, "cmd", r_str_get_fail (task->cmd, "null"));
		pj_end (pj);
		break;
	}
	default: {
		const char *info = task->cmd;
		if (task == core->tasks.main_task) {
			info = "-- MAIN TASK --";
		}
		r_cons_printf (core->cons, "%3d %3s %12s  %s\n",
					   task->id,
					   task->transient ? " (t)" : "",
					   r_core_task_status (task),
					   r_str_get (info));
		}
		break;
	}
}

R_API void r_core_task_list(RCore *core, int mode) {
	RListIter *iter;
	RCoreTask *task;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	// Snapshot tasks under lock to avoid printing while holding the lock
	TASK_SIGSET_T old_sigset;
	int running_count = 0;
	RList *snapshot = r_list_new ();
	if (!snapshot) {
		if (mode == 'j') {
			pj_free (pj);
		}
		return;
	}
	tasks_lock_enter (&core->tasks, &old_sigset);
	running_count = core->tasks.tasks_running;
	r_list_foreach (core->tasks.tasks, iter, task) {
		r_core_task_incref (task);
		r_list_append (snapshot, task);
	}
	tasks_lock_leave (&core->tasks, &old_sigset);

	r_list_foreach (snapshot, iter, task) {
		r_core_task_print (core, task, pj, mode);
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	} else {
		r_cons_printf (core->cons, "--\ntotal running: %d\n", running_count);
	}
	r_list_foreach (snapshot, iter, task) {
		r_core_task_decref (task);
	}
	r_list_free (snapshot);
}

R_API int r_core_task_running_tasks_count(RCoreTaskScheduler *scheduler) {
	RListIter *iter;
	RCoreTask *task;
	int count = 0;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	r_list_foreach (scheduler->tasks, iter, task) {
		if (task != scheduler->main_task && task->state != R_CORE_TASK_STATE_DONE) {
			count++;
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
	return count;
}

static void task_join(RCoreTask *task) {
	RThreadSemaphore *sem = task->running_sem;
	if (sem) {
		r_th_sem_wait (sem);
		r_th_sem_post (sem);
	}
}

R_API void r_core_task_join(RCoreTaskScheduler *scheduler, RCoreTask *current, int id) {
	if (current && id == current->id) {
		return;
	}
	if (id >= 0) {
		RCoreTask *task = r_core_task_get_incref (scheduler, id);
		if (!task) {
			return;
		}
		if (current) {
			r_core_task_sleep_begin (current);
		}
		task_join (task);
		if (current) {
			r_core_task_sleep_end (current);
		}
		r_core_task_decref (task);
	} else {
		TASK_SIGSET_T old_sigset;
		tasks_lock_enter (scheduler, &old_sigset);
		RList *tasks = r_list_clone (scheduler->tasks, NULL);
		RListIter *iter;
		RCoreTask *task;
		r_list_foreach (tasks, iter, task) {
			if (current == task) {
				continue;
			}
			r_core_task_incref (task);
		}
		tasks_lock_leave (scheduler, &old_sigset);

		r_list_foreach (tasks, iter, task) {
			if (current == task) {
				continue;
			}
			if (current) {
				r_core_task_sleep_begin (current);
			}
			task_join (task);
			if (current) {
				r_core_task_sleep_end (current);
			}
			r_core_task_decref (task);
		}
		r_list_free (tasks);
	}
}

static void task_free(RCoreTask *task) {
	if (!task) {
		return;
	}
	// TASK_SIGSET_T old_sigset;
	//tasks_lock_enter (scheduler, &old_sigset);

	RThread *thread = task->thread;
	RThreadLock *lock = task->dispatch_lock;
	if (lock) {
		r_th_lock_enter (lock);
	}
	free (task->cmd);
	free (task->res);
	if (thread) {
		r_th_free (thread);
	}
	r_th_sem_free (task->running_sem);
	r_th_cond_free (task->dispatch_cond);
	r_cons_context_free (task->cons_context);
	if (lock) {
		r_th_lock_leave (lock);
	}
	if (lock) {
		r_th_lock_free (lock); // task->dispatch_lock);
	}
	free (task);
	//tasks_lock_leave (scheduler, &old_sigset);
}

R_API RCoreTask *r_core_task_new(RCore *core, bool create_cons, const char *cmd, RCoreTaskCallback cb, void *user) {
	RCoreTask *task = R_NEW0 (RCoreTask);
	task->thread = NULL;
	task->cmd = cmd ? strdup (cmd) : NULL;
	task->cmd_log = false;
	task->res = NULL;
	task->running_sem = NULL;
	task->dispatched = false;
	task->dispatch_cond = r_th_cond_new ();
	task->dispatch_lock = r_th_lock_new (false);
	if (!task->dispatch_cond || !task->dispatch_lock) {
		goto hell;
	}

	if (create_cons) {
		task->cons_context = r_cons_context_clone (core->cons->context);
		if (!task->cons_context) {
			goto hell;
		}
		core->cur_cmd_depth = core->max_cmd_depth;
	}

	task->id = core->tasks.task_id_next++;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	task->refcount = 1;
	task->transient = false;
	task->core = core;
	task->user = user;
	task->cb = cb;

	return task;

hell:
	task_free (task);
	return NULL;
}

R_API void r_core_task_incref(RCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (&task->core->tasks, &old_sigset);
	task->refcount++;
	tasks_lock_leave (&task->core->tasks, &old_sigset);
}

R_API void r_core_task_decref(RCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	RCoreTaskScheduler *scheduler = &task->core->tasks;
	tasks_lock_enter (scheduler, &old_sigset);
	task->refcount--;
	if (task->refcount < 0) {
		// Guard against underflow; this should never happen
		R_LOG_WARN ("RCoreTask %d refcount underflow", task->id);
		task->refcount = 0;
	}
	if (task->refcount <= 0) {
		task_free (task);
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API void r_core_task_schedule(RCoreTask *current, RTaskState next_state) {
	if (!current) {
		return;
	}
	RCore *core = current->core;
	RCoreTaskScheduler *scheduler = &core->tasks;
	bool stop = next_state != R_CORE_TASK_STATE_RUNNING;

	R_CRITICAL_ENTER (core);
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	if (scheduler->oneshot_running || (!stop && scheduler->tasks_running == 1 && scheduler->oneshots_enqueued == 0)) {
		tasks_lock_leave (scheduler, &old_sigset);
		R_CRITICAL_LEAVE (core);
		return;
	}

	scheduler->current_task = NULL;

	current->state = next_state;

	if (stop) {
		if (scheduler->tasks_running > 0) {
			scheduler->tasks_running--;
		}
	}

	// oneshots always have priority.
	// if there are any queued, run them immediately.
	OneShot *oneshot;
	while ( (oneshot = r_list_pop_head (scheduler->oneshot_queue))) {
		scheduler->oneshots_enqueued--;
		scheduler->oneshot_running = true;
		oneshot->func (oneshot->user);
		scheduler->oneshot_running = false;
		free (oneshot);
	}

	RCoreTask *next = r_list_pop_head (scheduler->tasks_queue);

	if (next && !stop) {
		r_list_append (scheduler->tasks_queue, current);
		r_th_lock_enter (current->dispatch_lock);
	}

	tasks_lock_leave (scheduler, &old_sigset);

	if (next) {
		r_cons_context_reset (current->cons_context);
		r_th_lock_enter (next->dispatch_lock);
		next->dispatched = true;
		r_th_lock_leave (next->dispatch_lock);
		r_th_cond_signal (next->dispatch_cond);
		if (!stop) {
			while (!current->dispatched) {
				r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
			}
			current->dispatched = false;
			r_th_lock_leave (current->dispatch_lock);
		}
	}

	if (!stop) {
		scheduler->current_task = current;
		if (current->cons_context) {
			r_cons_context_load (current->cons_context);
		}
		// else: no context to load/reset; keep current
	}
	R_CRITICAL_LEAVE (core);
}

// task_wakeup was previously a cooperative scheduler entrypoint. The current
// model is thread-per-task and synchronous main-task execution. Keep state
// management local to call sites; no separate wakeup routine is needed.

R_API void r_core_task_yield(RCoreTaskScheduler *scheduler) {
	RCoreTask *task = r_core_task_self (scheduler);
	if (!task) {
		return;
	}
	r_core_task_schedule (task, R_CORE_TASK_STATE_RUNNING);
}

static void task_end(RCoreTask *t) {
	r_core_task_schedule (t, R_CORE_TASK_STATE_DONE);
}

static RThreadFunctionRet task_run(RCoreTask *task) {
	if (!task) {
		return 0;
	}
	RCore *core = task->core;
	RCoreTaskScheduler *scheduler = &task->core->tasks;

	// Mark running and account the task under scheduler lock
	TASK_SIGSET_T __old_sigset;
	tasks_lock_enter (scheduler, &__old_sigset);
	task->state = R_CORE_TASK_STATE_RUNNING;
	scheduler->tasks_running++;
	tasks_lock_leave (scheduler, &__old_sigset);

	if (task->cons_context && task->cons_context->breaked) {
		// breaked in R_CORE_TASK_STATE_BEFORE_START
		goto stillbirth;
	}

	RCore *local_core = mycore_new (core);
	char *res_str;
	if (task == scheduler->main_task) {
		r_core_cmd (local_core, task->cmd, task->cmd_log);
		res_str = NULL;
	} else {
		res_str = r_core_cmd_str (local_core, task->cmd);
	}
	mycore_free (local_core);

	free (task->res);
	task->res = res_str;

#if 0
	if (task != scheduler->main_task && r_cons_default_context_is_interactive ()) {
		R_LOG_INFO ("Task %d finished", task->id);
	}
#endif

	TASK_SIGSET_T old_sigset;
stillbirth:
	tasks_lock_enter (scheduler, &old_sigset);

	task_end (task);

	if (task->cb) {
		task->cb (task->user, task->res);
	}

	if (task->running_sem) {
		r_th_sem_post (task->running_sem);
	}

	if (task->cons_context && task->cons_context->break_stack) {
		r_cons_context_break_pop (core->cons, task->cons_context, false);
	}

	int ret = R_TH_STOP;
	if (task->transient) {
		RCoreTask *ltask;
		RListIter *iter;
		r_list_foreach (scheduler->tasks, iter, ltask) {
			if (ltask == task) {
				r_list_delete (scheduler->tasks, iter);
				ret = R_TH_FREED;
				break;
			}
		}
	}

	tasks_lock_leave (scheduler, &old_sigset);
	return ret;
}

static RThreadFunctionRet task_run_thread(RThread *th) {
	if (!th) {
		return 0;
	}
	RCoreTask *task = (RCoreTask *)th->user;
	// Set TLS current task for this thread during execution
	task_tls_current = task;
	RThreadFunctionRet ret = task_run (task);
	// Clear TLS on exit
	task_tls_current = NULL;
	return ret;
}

R_API void r_core_task_enqueue(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	if (!scheduler || !task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	if (!task->running_sem) {
		task->running_sem = r_th_sem_new (1);
	}
	if (task->running_sem) {
		r_th_sem_wait (task->running_sem);
	}
	if (task->cons_context) {
		r_cons_context_break_push (task->core->cons, task->cons_context, NULL, NULL, false);
	}
	r_list_append (scheduler->tasks, task);
	task->thread = r_th_new (task_run_thread, task, 0);
	r_th_start (task->thread);

	tasks_lock_leave (scheduler, &old_sigset);
}

R_API void r_core_task_enqueue_oneshot(RCoreTaskScheduler *scheduler, RCoreTaskOneShot func, void *user) {
	if (!scheduler || !func) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	bool run_now = false;
	tasks_lock_enter (scheduler, &old_sigset);
	if (scheduler->tasks_running == 0) {
		// Execute outside the scheduler lock to avoid deadlocks
		scheduler->oneshot_running = true;
		run_now = true;
	} else {
		OneShot *oneshot = R_NEW (OneShot);
		if (oneshot) {
			oneshot->func = func;
			oneshot->user = user;
			r_list_append (scheduler->oneshot_queue, oneshot);
			scheduler->oneshots_enqueued++;
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);

	if (run_now) {
		func (user);
		tasks_lock_enter (scheduler, &old_sigset);
		scheduler->oneshot_running = false;
		tasks_lock_leave (scheduler, &old_sigset);
	}
}

R_API int r_core_task_run_sync(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	R_RETURN_VAL_IF_FAIL (scheduler && task, -1);
	task->thread = NULL;
	// Set TLS for synchronous execution within the current thread
	task_tls_current = task;
	RThreadFunctionRet ret = task_run (task);
	// Clear TLS after execution
	task_tls_current = NULL;
	return ret;
}

/* begin running stuff synchronously on the main task */
R_API void r_core_task_sync_begin(RCoreTaskScheduler *scheduler) {
	if (!scheduler) {
		return;
	}
	RCoreTask *task = scheduler->main_task;
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	task->thread = NULL;
	task->cmd = NULL;
	task->cmd_log = false;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	tasks_lock_leave (scheduler, &old_sigset);
	// Mark main task running and ensure its console context is active
	tasks_lock_enter (scheduler, &old_sigset);
	task->state = R_CORE_TASK_STATE_RUNNING;
	tasks_lock_leave (scheduler, &old_sigset);
	if (task->cons_context) {
		r_cons_context_load (task->cons_context);
	}
}

/* end running stuff synchronously, initially started with r_core_task_sync_begin () */
R_API void r_core_task_sync_end(RCoreTaskScheduler *scheduler) {
	R_RETURN_IF_FAIL (scheduler);
	task_end (scheduler->main_task);
}

/* To be called from within a task. Begin sleeping and schedule other tasks until r_core_task_sleep_end () is called. */
R_API void r_core_task_sleep_begin(RCoreTask *task) {
	R_RETURN_IF_FAIL (task);
	r_core_task_schedule (task, R_CORE_TASK_STATE_SLEEPING);
}

R_API void r_core_task_sleep_end(RCoreTask *task) {
	R_RETURN_IF_FAIL (task);
	// Return to RUNNING state and restore context via scheduler path
	r_core_task_schedule (task, R_CORE_TASK_STATE_RUNNING);
}

R_API const char *r_core_task_status(RCoreTask *task) {
	if (!task) {
		return NULL;
	}
	switch (task->state) {
	case R_CORE_TASK_STATE_RUNNING:
		return "running";
	case R_CORE_TASK_STATE_SLEEPING:
		return "sleeping";
	case R_CORE_TASK_STATE_DONE:
		return "done";
	case R_CORE_TASK_STATE_BEFORE_START:
		return "before start";
	default:
		return "unknown";
	}
}

R_API RCoreTask *r_core_task_self(RCoreTaskScheduler *scheduler) {
	if (!scheduler) {
		return NULL;
	}
	// Prefer TLS current task if set; fall back to scheduler state
	if (task_tls_current) {
		return task_tls_current;
	}
	RCoreTask *res = scheduler->current_task ? scheduler->current_task : scheduler->main_task;
	return res;
}

static RCoreTask *task_get(RCoreTaskScheduler *scheduler, int id) {
	if (!scheduler) {
		return NULL;
	}
	RCoreTask *task;
	RListIter *iter;
	r_list_foreach (scheduler->tasks, iter, task) {
		if (task->id == id) {
			return task;
		}
	}
	return NULL;
}

R_API RCoreTask *r_core_task_get_incref(RCoreTaskScheduler *scheduler, int id) {
	if (!scheduler) {
		return NULL;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RCoreTask *task = task_get (scheduler, id);
	if (task) {
		r_core_task_incref (task);
	}
	tasks_lock_leave (scheduler, &old_sigset);
	return task;
}

R_API void r_core_task_break(RCoreTaskScheduler *scheduler, int id) {
	if (!scheduler) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RCoreTask *task = task_get (scheduler, id);
	if (!task || task->state == R_CORE_TASK_STATE_DONE) {
		tasks_lock_leave (scheduler, &old_sigset);
		return;
	}
	if (task->cons_context) {
		r_cons_context_break (task->cons_context);
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API void r_core_task_break_all(RCoreTaskScheduler *scheduler) {
	if (!scheduler) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RCoreTask *task;
	RListIter *iter;
	r_list_foreach (scheduler->tasks, iter, task) {
		if (task && task->state != R_CORE_TASK_STATE_DONE) {
			r_cons_context_break (task->cons_context);
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API int r_core_task_del(RCoreTaskScheduler *scheduler, int id) {
	if (!scheduler) {
		return 0;
	}
	RCoreTask *task;
	RListIter *iter;
	bool ret = false;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	r_list_foreach (scheduler->tasks, iter, task) {
		if (task->id == id) {
			if (task == scheduler->main_task) {
				break;
			}
			if (task->state == R_CORE_TASK_STATE_DONE) {
				r_list_delete (scheduler->tasks, iter);
			} else {
				task->transient = true;
			}
			ret = true;
			break;
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
	return ret;
}

R_API void r_core_task_del_all_done(RCoreTaskScheduler *scheduler) {
	if (!scheduler) {
		return;
	}
	RCoreTask *task;
	RListIter *iter, *iter2;
	r_list_foreach_safe (scheduler->tasks, iter, iter2, task) {
		if (task != scheduler->main_task && task->state == R_CORE_TASK_STATE_DONE) {
			r_list_delete (scheduler->tasks, iter);
		}
	}
}
