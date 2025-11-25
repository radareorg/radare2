/* radare - LGPL - Copyright 2014-2025 - pancake */

#include <r_core.h>

// Per-thread current task pointer (TLS)
static R_TH_LOCAL RCoreTask *task_tls_current = NULL;

// Internal helpers (not exposed in headers)
static RCore *r_core_clone_for_task(RCore *core);
static int _task_run_threaded(RCoreTaskScheduler *scheduler, RCoreTask *task);
static int _task_run_forked(RCoreTaskScheduler *scheduler, RCoreTask *task);

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
	tasks->tasks = r_list_newf ((RListFree)r_core_task_free);
	tasks->tasks_queue = r_list_new ();
	tasks->lock = r_th_lock_new (true);
	tasks->tasks_running = 0;
	tasks->main_task = r_core_task_new (core, R_CORE_TASK_MODE_COOP, false, NULL, NULL, NULL);
	r_list_append (tasks->tasks, tasks->main_task);
	tasks->foreground_task = tasks->main_task;
	tasks->default_mode = R_CORE_TASK_MODE_COOP;
	tasks->main_core = core;
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
static void tasks_lock_block_signals(TASK_SIGSET_T *old_sigset) {
	(void)old_sigset;
}
static void tasks_lock_block_signals_reset(TASK_SIGSET_T *old_sigset) {
	(void)old_sigset;
}
#endif

static void tasks_lock_enter(RCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	tasks_lock_block_signals (old_sigset);
	r_th_lock_enter (scheduler->lock);
}

static void tasks_lock_leave(RCoreTaskScheduler *scheduler, TASK_SIGSET_T *old_sigset) {
	r_th_lock_leave (scheduler->lock);
	tasks_lock_block_signals_reset (old_sigset);
}

/* OneShot support removed */

static const char *state_tostring(int s) {
	switch (s) {
	case R_CORE_TASK_STATE_BEFORE_START:
		return "before_start";
	case R_CORE_TASK_STATE_RUNNING:
		return "running";
	case R_CORE_TASK_STATE_SLEEPING:
		return "sleeping";
	case R_CORE_TASK_STATE_DONE:
		return "done";
	}
	return "unknown";
}

static const char *mode_tostring(RCoreTaskMode m) {
	switch (m) {
	case R_CORE_TASK_MODE_COOP:
		return "coop";
	case R_CORE_TASK_MODE_THREAD:
		return "thread";
	case R_CORE_TASK_MODE_FORK:
		return "fork";
	}
	return "unknown";
}

static void r_core_task_print(RCore *core, RCoreTask *task, PJ *pj, int mode) {
	switch (mode) {
	case 'j':
		pj_o (pj);
		pj_ki (pj, "id", task->id);
		pj_ks (pj, "mode", mode_tostring (task->mode));
		pj_kb (pj, "foreground", task == core->tasks.foreground_task);
		pj_ks (pj, "state", state_tostring (task->state));
		pj_kb (pj, "transient", task->transient);
		const char *cmd_info = task->cmd;
		if (task == core->tasks.main_task) {
			cmd_info = "-- MAIN TASK --";
		}
		pj_ks (pj, "cmd", cmd_info);
		pj_end (pj);
		break;
	default:
		{
			const char *info = task->cmd;
			if (task == core->tasks.main_task) {
				info = "-- MAIN TASK --";
			}
			r_cons_printf (core->cons, "%3d %3s %12s  %s\n",
				task->id,
				task->transient? " (t)": "",
				r_core_task_status (task),
				r_str_get (info));
		}
		break;
	}
}

R_API void r_core_task_list(RCore *core, int mode) {
	RListIter *iter;
	RCoreTask *task;
	RTable *t = NULL;
	PJ *pj = NULL;

	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	} else {
		t = r_core_table_new (core, "tasks");
		RTableColumnType *typeNumber = r_table_type ("number");
		RTableColumnType *typeString = r_table_type ("string");
		RTableColumnType *typeBool = r_table_type ("bool");
		r_table_add_column (t, typeNumber, "id", 0);
		r_table_add_column (t, typeString, "mode", 0);
		r_table_add_column (t, typeString, "fg", 0);
		r_table_add_column (t, typeString, "state", 0);
		r_table_add_column (t, typeBool, "transient", 0);
		r_table_add_column (t, typeString, "cmd", 0);
	}

	// Snapshot tasks under lock to avoid printing while holding the lock
	TASK_SIGSET_T old_sigset;
	int running_count = 0;
	RList *snapshot = r_list_new ();
	if (!snapshot) {
		if (mode == 'j') {
			pj_free (pj);
		} else {
			r_table_free (t);
		}
		return;
	}
	tasks_lock_enter (&core->tasks, &old_sigset);
	running_count = core->tasks.tasks_running;
	r_list_foreach (core->tasks.tasks, iter, task) {
		r_list_append (snapshot, task);
	}
	tasks_lock_leave (&core->tasks, &old_sigset);

	r_list_foreach (snapshot, iter, task) {
		if (mode == 'j') {
			r_core_task_print (core, task, pj, mode);
		} else {
			const char *info = task->cmd;
			if (task == core->tasks.main_task) {
				info = "-- MAIN TASK --";
			}
			const char *fg = (task == core->tasks.foreground_task) ? "*" : "";
			{
				RList *items = r_list_newf (free);
				r_list_append (items, r_str_newf ("%d", task->id));
				r_list_append (items, strdup (mode_tostring (task->mode)));
				r_list_append (items, strdup (fg));
				r_list_append (items, strdup (r_core_task_status (task)));
				r_list_append (items, strdup (r_str_bool (task->transient)));
				r_list_append (items, strdup (r_str_get (info)));
				r_table_add_row_list (t, items);
			}
		}
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	} else {
		if (r_table_query (t, "")) {
			char *s = r_table_tostring (t);
			r_cons_printf (core->cons, "%s\n", s);
			free (s);
		}
		r_cons_printf (core->cons, "total running: %d\n", running_count);
		r_table_free (t);
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
		RCoreTask *task = r_core_task_get (scheduler, id);
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
	} else {
		TASK_SIGSET_T old_sigset;
		tasks_lock_enter (scheduler, &old_sigset);
		RList *tasks = r_list_clone (scheduler->tasks, NULL);
		RListIter *iter;
		RCoreTask *task;
		// snapshot holds raw pointers only
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
			/* no refcounting */
		}
		r_list_free (tasks);
	}
}

static void task_free(RCoreTask *task) {
	if (!task) {
		return;
	}
	// TASK_SIGSET_T old_sigset;
	// tasks_lock_enter (scheduler, &old_sigset);

	RThread *thread = task->thread;
	RThreadLock *lock = task->dispatch_lock;
	if (lock) {
		r_th_lock_enter (lock);
	}
	free (task->cmd);
	free (task->res);
	r_th_free (thread);
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
	// tasks_lock_leave (scheduler, &old_sigset);
}

R_API RCoreTask *r_core_task_new(RCore *core, RCoreTaskMode mode, bool create_cons, const char *cmd, RCoreTaskCallback cb, void *user) {
	RCoreTask *task = R_NEW0 (RCoreTask);
	task->thread = NULL;
	task->cmd = cmd? strdup (cmd): NULL;
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
	task->transient = false;
	task->core = core;
	// Accept -1 as "use cooperative default"
	if ((int)mode == -1) {
		mode = R_CORE_TASK_MODE_COOP;
	}
	task->mode = mode;
	task->task_core = NULL;
	task->pid = -1;
	task->user = user;
	task->cb = cb;

	return task;

hell:
	task_free (task);
	return NULL;
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
	if ((!stop && scheduler->tasks_running == 1)) {
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

	/* oneshot support removed */

	RCoreTask *next = r_list_pop_head (scheduler->tasks_queue);

	if (next && !stop) {
		r_list_append (scheduler->tasks_queue, current);
		r_th_lock_enter (current->dispatch_lock);
	}

	tasks_lock_leave (scheduler, &old_sigset);

	if (next) {
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

	if (core && core->ev) {
		r_event_send (core->ev, R_EVENT_CORE_TASK_STARTED, task);
	}

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

	// Determine interruption vs finished
	bool interrupted = false;
	if (task->cons_context && task->cons_context->breaked) {
		interrupted = true;
	}

	if (task->cb) {
		task->cb (task->user, task->res);
	}

	if (task->running_sem) {
		r_th_sem_post (task->running_sem);
	}

#if 0
	if (task->cons_context && task->cons_context->break_stack && task->mode != R_CORE_TASK_MODE_COOP) {
		r_cons_context_break_pop (core->cons, task->cons_context, false);
	}
#endif

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
	if (core && core->ev) {
		const int et = interrupted? R_EVENT_CORE_TASK_INTERRUPTED: R_EVENT_CORE_TASK_FINISHED;
		r_event_send (core->ev, et, task);
	}
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
	RCoreTask *res = scheduler->current_task? scheduler->current_task: scheduler->main_task;
	return res;
}

R_API RCoreTask *r_core_task_get(RCoreTaskScheduler *scheduler, int id) {
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

R_API void r_core_task_set_foreground(RCoreTaskScheduler *scheduler, int task_id) {
	R_RETURN_IF_FAIL (scheduler);
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RCoreTask *t = r_core_task_get (scheduler, task_id);
	if (t) {
		scheduler->foreground_task = t;
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API RCoreTask *r_core_task_get_foreground(RCoreTaskScheduler *scheduler) {
	R_RETURN_VAL_IF_FAIL (scheduler, NULL);
	return scheduler->foreground_task? scheduler->foreground_task: scheduler->main_task;
}

static int _task_run_threaded(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	R_RETURN_VAL_IF_FAIL (scheduler && task, -1);
	task->mode = R_CORE_TASK_MODE_THREAD;
	if (!task->task_core) {
		task->task_core = r_core_clone_for_task (task->core);
	}
	r_core_task_enqueue (scheduler, task);
	return task->id;
}

static int _task_run_forked(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	R_RETURN_VAL_IF_FAIL (scheduler && task, -1);

#if R2__WINDOWS__ || defined(__EMSCRIPTEN__)
	// Fork mode is not supported on Windows or WebAssembly
	R_LOG_WARN ("task: fork mode is not supported on this platform; running in thread mode instead");
	return _task_run_threaded (scheduler, task);
#else
	task->mode = R_CORE_TASK_MODE_FORK;
	if (!task->task_core) {
		task->task_core = r_core_clone_for_task (task->core);
	}
	/* result_pipe removed */
	r_core_task_enqueue (scheduler, task);
	return task->id;
#endif
}

static RCore *r_core_clone_for_task(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	return mycore_new (core);
}

R_API void r_core_task_set_default_mode(RCoreTaskScheduler *scheduler, RCoreTaskMode mode) {
	R_RETURN_IF_FAIL (scheduler);
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
#if R2__WINDOWS__ || defined(__EMSCRIPTEN__)
	if (mode == R_CORE_TASK_MODE_FORK) {
		// Disallow fork default on unsupported platforms
		scheduler->default_mode = R_CORE_TASK_MODE_THREAD;
		R_LOG_WARN ("Cannot use FORK tasks on this platform");
	} else {
		scheduler->default_mode = mode;
	}
#else
	scheduler->default_mode = mode;
#endif
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API RCoreTaskMode r_core_task_get_default_mode(RCoreTaskScheduler *scheduler) {
	return R_CORE_TASK_MODE_COOP;
}

R_API int r_core_task_run(RCoreTaskScheduler *scheduler, RCoreTask *task, int mode) {
	R_RETURN_VAL_IF_FAIL (scheduler && task, -1);
	RCoreTaskMode m = (mode < 0)? r_core_task_get_default_mode (scheduler): (RCoreTaskMode)mode;
	switch (m) {
	case R_CORE_TASK_MODE_COOP:
		// cooperative: run synchronously in scheduler context
		return r_core_task_run_sync (scheduler, task);
	case R_CORE_TASK_MODE_THREAD:
		return _task_run_threaded (scheduler, task);
	case R_CORE_TASK_MODE_FORK:
		return _task_run_forked (scheduler, task);
	}
	return -1;
}

R_API int r_core_task_run_threaded(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	return _task_run_threaded (scheduler, task);
}
R_API int r_core_task_run_forked(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	return _task_run_forked (scheduler, task);
}

/* Minimal lifecycle API implementation */
R_API RCoreTask *r_core_task_submit(RCore *core, const char *cmd, RCoreTaskCallback cb, void *user, bool capture_cons, int mode) {
	R_RETURN_VAL_IF_FAIL (core && cmd, NULL);
	RCoreTaskMode m = (mode < 0)? core->tasks.default_mode: (RCoreTaskMode)mode;
	RCoreTask *t = r_core_task_new (core, m, capture_cons, cmd, cb, user);
	if (!t) {
		return NULL;
	}
	if (m == R_CORE_TASK_MODE_COOP) {
		// Run synchronously on current thread
		r_core_task_run_sync (&core->tasks, t);
	} else if (m == R_CORE_TASK_MODE_THREAD) {
		_task_run_threaded (&core->tasks, t);
	} else {
		_task_run_forked (&core->tasks, t);
	}
	return t;
}

R_API int r_core_task_id(const RCoreTask *t) {
	return t? t->id: -1;
}

R_API bool r_core_task_wait(RCoreTask *t, ut64 timeout_ms) {
	R_RETURN_VAL_IF_FAIL (t, false);
	if (!t->thread) {
		// Synchronous or already joined
		return true;
	}
	if (timeout_ms == 0) {
		return t->state == R_CORE_TASK_STATE_DONE;
	}
	// Fallback: blocking wait (no timed wait API in r_th)
	r_th_wait (t->thread);
	return true;
}

R_API bool r_core_task_cancel(RCoreTask *t, bool hard) {
	R_RETURN_VAL_IF_FAIL (t, false);
#if R2__WINDOWS__
	// cant hard cancel
#else
	if (hard && t->mode == R_CORE_TASK_MODE_FORK && t->pid > 0) {
		return r_sandbox_kill (t->pid, 9) == 0;
	}
#endif
	// Cooperative: request break via cons context if present
	if (t->cons_context) {
		r_cons_context_break (t->cons_context);
		return true;
	}
	return false;
}

/* Cancel all running or pending tasks in the scheduler */
R_API void r_core_task_cancel_all(RCore *core, bool hard) {
	R_RETURN_IF_FAIL (core);
	RCoreTaskScheduler *scheduler = &core->tasks;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RListIter *it;
	RCoreTask *t;
	r_list_foreach (scheduler->tasks, it, t) {
		if (!t) {
			continue;
		}
		if (t->state != R_CORE_TASK_STATE_DONE) {
			/* avoid killing the main task; only request break */
			if (t == scheduler->main_task) {
				if (t->cons_context) {
					r_cons_context_break (t->cons_context);
				}
				continue;
			}
			/* release lock while canceling to avoid potential callbacks deadlocks */
			tasks_lock_leave (scheduler, &old_sigset);
			r_core_task_cancel (t, hard);
			tasks_lock_enter (scheduler, &old_sigset);
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API void r_core_task_free(RCoreTask *t) {
	if (t && t->thread) {
		r_th_wait (t->thread);
	}
}
