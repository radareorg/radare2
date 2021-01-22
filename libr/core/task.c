/* radare - LGPL - Copyright 2014-2019 - pancake, thestr4ng3r */

#include <r_core.h>

R_API void r_core_task_scheduler_init (RCoreTaskScheduler *tasks, RCore *core) {
	tasks->task_id_next = 0;
	tasks->tasks = r_list_newf ((RListFree)r_core_task_decref);
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

R_API void r_core_task_scheduler_fini (RCoreTaskScheduler *tasks) {
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
static void tasks_lock_block_signals(TASK_SIGSET_T *old_sigset) { (void)old_sigset; }
static void tasks_lock_block_signals_reset(TASK_SIGSET_T *old_sigset) { (void)old_sigset; }
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

R_API void r_core_task_print (RCore *core, RCoreTask *task, PJ *pj, int mode) {
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
		r_cons_printf ("%3d %3s %12s  %s\n",
					   task->id,
					   task->transient ? "(t)" : "",
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
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (&core->tasks, &old_sigset);
	r_list_foreach (core->tasks.tasks, iter, task) {
		r_core_task_print (core, task, pj, mode);
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	} else {
		r_cons_printf ("--\ntotal running: %d\n", core->tasks.tasks_running);
	}
	tasks_lock_leave (&core->tasks, &old_sigset);
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
	if (!sem) {
		return;
	}

	r_th_sem_wait (sem);
	r_th_sem_post (sem);
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
		RList *tasks = r_list_clone (scheduler->tasks);
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

static void task_free (RCoreTask *task) {
	if (!task) {
		return;
	}
	free (task->cmd);
	free (task->res);
	r_th_free (task->thread);
	r_th_sem_free (task->running_sem);
	r_th_cond_free (task->dispatch_cond);
	r_th_lock_free (task->dispatch_lock);
	r_cons_context_free (task->cons_context);
	free (task);
}

R_API RCoreTask *r_core_task_new(RCore *core, bool create_cons, const char *cmd, RCoreTaskCallback cb, void *user) {
	RCoreTask *task = R_NEW0 (RCoreTask);
	if (!task) {
		goto hell;
	}

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
		task->cons_context = r_cons_context_new (r_cons_singleton ()->context);
		if (!task->cons_context) {
			goto hell;
		}
		task->cons_context->cmd_depth = core->max_cmd_depth;
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

R_API void r_core_task_incref (RCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (&task->core->tasks, &old_sigset);
	task->refcount++;
	tasks_lock_leave (&task->core->tasks, &old_sigset);
}

R_API void r_core_task_decref (RCoreTask *task) {
	if (!task) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	RCoreTaskScheduler *scheduler = &task->core->tasks;
	tasks_lock_enter (scheduler, &old_sigset);
	task->refcount--;
	if (task->refcount <= 0) {
		task_free (task);
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API void r_core_task_schedule(RCoreTask *current, RTaskState next_state) {
	RCore *core = current->core;
	RCoreTaskScheduler *scheduler = &core->tasks;
	bool stop = next_state != R_CORE_TASK_STATE_RUNNING;

	if (scheduler->oneshot_running || (!stop && scheduler->tasks_running == 1 && scheduler->oneshots_enqueued == 0)) {
		return;
	}

	scheduler->current_task = NULL;

	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);

	current->state = next_state;

	if (stop) {
		scheduler->tasks_running--;
	}

	// oneshots always have priority.
	// if there are any queued, run them immediately.
	OneShot *oneshot;
	while ((oneshot = r_list_pop_head (scheduler->oneshot_queue))) {
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
		r_cons_context_reset ();
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
		} else {
			r_cons_context_reset ();
		}
	}
}

static void task_wakeup(RCoreTask *current) {
	RCore *core = current->core;
	RCoreTaskScheduler *scheduler = &core->tasks;

	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);

	scheduler->tasks_running++;
	current->state = R_CORE_TASK_STATE_RUNNING;

	// check if there are other tasks running
	bool single = scheduler->tasks_running == 1 || scheduler->tasks_running == 0;

	r_th_lock_enter (current->dispatch_lock);

	// if we are not the only task, we must wait until another task signals us.

	if (!single) {
		r_list_append (scheduler->tasks_queue, current);
	}

	tasks_lock_leave (scheduler, &old_sigset);

	if (!single) {
		while (!current->dispatched) {
			r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
		}
		current->dispatched = false;
	}

	r_th_lock_leave (current->dispatch_lock);

	scheduler->current_task = current;

	if (current->cons_context) {
		r_cons_context_load (current->cons_context);
	} else {
		r_cons_context_reset ();
	}
}

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
	RCore *core = task->core;
	RCoreTaskScheduler *scheduler = &task->core->tasks;

	task_wakeup (task);

	if (task->cons_context && task->cons_context->breaked) {
		// breaked in R_CORE_TASK_STATE_BEFORE_START
		goto stillbirth;
	}

	char *res_str;
	if (task == scheduler->main_task) {
		r_core_cmd (core, task->cmd, task->cmd_log);
		res_str = NULL;
	} else {
		res_str = r_core_cmd_str (core, task->cmd);
	}

	free (task->res);
	task->res = res_str;

	if (task != scheduler->main_task && r_cons_default_context_is_interactive ()) {
		eprintf ("\nTask %d finished\n", task->id);
	}

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
		r_cons_context_break_pop (task->cons_context, false);
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
	RCoreTask *task = (RCoreTask *)th->user;
	return task_run (task);
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
		r_cons_context_break_push (task->cons_context, NULL, NULL, false);
	}
	r_list_append (scheduler->tasks, task);
	task->thread = r_th_new (task_run_thread, task, 0);
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API void r_core_task_enqueue_oneshot(RCoreTaskScheduler *scheduler, RCoreTaskOneShot func, void *user) {
	if (!scheduler || !func) {
		return;
	}
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	if (scheduler->tasks_running == 0) {
		// nothing is running right now and no other task can be scheduled
		// while core->tasks_lock is locked => just run it
		scheduler->oneshot_running = true;
		func (user);
		scheduler->oneshot_running = false;
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
}

R_API int r_core_task_run_sync(RCoreTaskScheduler *scheduler, RCoreTask *task) {
	task->thread = NULL;
	return task_run (task);
}

/* begin running stuff synchronously on the main task */
R_API void r_core_task_sync_begin(RCoreTaskScheduler *scheduler) {
	RCoreTask *task = scheduler->main_task;
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	task->thread = NULL;
	task->cmd = NULL;
	task->cmd_log = false;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	tasks_lock_leave (scheduler, &old_sigset);
	task_wakeup (task);
}

/* end running stuff synchronously, initially started with r_core_task_sync_begin() */
R_API void r_core_task_sync_end(RCoreTaskScheduler *scheduler) {
	task_end (scheduler->main_task);
}

/* To be called from within a task.
 * Begin sleeping and schedule other tasks until r_core_task_sleep_end() is called. */
R_API void r_core_task_sleep_begin(RCoreTask *task) {
	r_core_task_schedule (task, R_CORE_TASK_STATE_SLEEPING);
}

R_API void r_core_task_sleep_end(RCoreTask *task) {
	task_wakeup (task);
}

R_API const char *r_core_task_status (RCoreTask *task) {
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

R_API RCoreTask *r_core_task_self (RCoreTaskScheduler *scheduler) {
	return scheduler->current_task ? scheduler->current_task : scheduler->main_task;
}

static RCoreTask *task_get (RCoreTaskScheduler *scheduler, int id) {
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
	TASK_SIGSET_T old_sigset;
	tasks_lock_enter (scheduler, &old_sigset);
	RCoreTask *task;
	RListIter *iter;
	r_list_foreach (scheduler->tasks, iter, task) {
		if (task->state != R_CORE_TASK_STATE_DONE) {
			r_cons_context_break (task->cons_context);
		}
	}
	tasks_lock_leave (scheduler, &old_sigset);
}

R_API int r_core_task_del (RCoreTaskScheduler *scheduler, int id) {
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

R_API void r_core_task_del_all_done (RCoreTaskScheduler *scheduler) {
	RCoreTask *task;
	RListIter *iter, *iter2;
	r_list_foreach_safe (scheduler->tasks, iter, iter2, task) {
		if (task != scheduler->main_task && task->state == R_CORE_TASK_STATE_DONE) {
			r_list_delete (scheduler->tasks, iter);
		}
	}
}
