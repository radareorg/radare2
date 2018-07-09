/* radare - LGPL - Copyright 2014-2018 - pancake, thestr4ng3r */

#include <r_core.h>

typedef struct oneshot_t {
	RCoreTaskOneShot func;
	void *user;
} OneShot;

R_API void r_core_task_print (RCore *core, RCoreTask *task, int mode) {
	switch (mode) {
	case 'j':
		r_cons_printf ("{\"id\":%d,\"state\":\"", task->id);
		switch (task->state) {
			case R_CORE_TASK_STATE_BEFORE_START:
				r_cons_print ("before_start");
				break;
			case R_CORE_TASK_STATE_RUNNING:
				r_cons_print ("running");
				break;
			case R_CORE_TASK_STATE_SLEEPING:
				r_cons_print ("sleeping");
				break;
			case R_CORE_TASK_STATE_DONE:
				r_cons_print ("done");
				break;
		}
		r_cons_print ("\",\"cmd\":");
		if (task->cmd) {
			r_cons_printf ("\"%s\"}", task->cmd);
		} else {
			r_cons_printf ("null}");
		}
		break;
	default: {
		const char *info = task->cmd;
		if (task == core->main_task) {
			info = "-- MAIN TASK --";
		}
		r_cons_printf ("%2d  %12s  %s\n",
					   task->id,
					   r_core_task_status (task),
					   info ? info : "");
		break;
	}
	}
}

R_API void r_core_task_list(RCore *core, int mode) {
	RListIter *iter;
	RCoreTask *task;
	if (mode == 'j') {
		r_cons_printf ("[");
	}
	r_th_lock_enter (core->tasks_lock);
	r_list_foreach (core->tasks, iter, task) {
		r_core_task_print (core, task, mode);
		if (mode == 'j' && iter->n) {
			r_cons_printf (",");
		}
	}
	if (mode == 'j') {
		r_cons_printf ("]\n");
	} else {
		r_cons_printf ("--\ntotal running: %d\n", core->tasks_running);
	}
	r_th_lock_leave (core->tasks_lock);
}

static void task_join(RCoreTask *task) {
	RThreadSemaphore *sem = task->running_sem;
	if (!sem) {
		return;
	}
	r_th_sem_wait (sem);
	r_th_sem_post (sem);
}

R_API void r_core_task_join(RCore *core, RCoreTask *current, RCoreTask *task) {
	RListIter *iter;
	if (current && task == current) {
		return;
	}
	if (task) {
		if (current) {
			r_core_task_sleep_begin (current);
		}
		task_join (task);
		if (current) {
			r_core_task_sleep_end (current);
		}
	} else {
		r_list_foreach_prev (core->tasks, iter, task) {
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
		}
	}
}

R_API RCoreTask *r_core_task_new(RCore *core, bool create_cons, const char *cmd, RCoreTaskCallback cb, void *user) {
	if (cmd && *cmd == '=') {
		eprintf ("=* commands disabled in tasks\n");
		return NULL;
	}
	RCoreTask *task = R_NEW0 (RCoreTask);
	if (!task) {
		goto hell;
	}

	task->thread = NULL;
	task->cmd = cmd ? strdup (cmd) : NULL;
	task->cmd_log = false;
	task->res = NULL;
	task->running_sem = NULL;
	task->dispatch_cond = r_th_cond_new ();
	task->dispatch_lock = r_th_lock_new (false);
	if (!task->dispatch_cond || !task->dispatch_lock) {
		goto hell;
	}

	if (create_cons) {
		task->cons_context = r_cons_context_new ();
		if (!task->cons_context) {
			goto hell;
		}
	}

	task->id = core->task_id_next++;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	task->core = core;
	task->user = user;
	task->cb = cb;

	return task;

hell:
	r_core_task_free (task);
	return NULL;
}

R_API void r_core_task_free (RCoreTask *task) {
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

R_API void r_core_task_schedule(RCoreTask *current, RTaskState next_state) {
	RCore *core = current->core;
	bool stop = next_state != R_CORE_TASK_STATE_RUNNING;

	if (!stop && core->tasks_running == 1) {
		return;
	}

	core->current_task = NULL;
	
	r_th_lock_enter (core->tasks_lock);

	current->state = next_state;

	if (stop) {
		core->tasks_running--;
		r_th_lock_leave (current->dispatch_lock);
	}

	// oneshots always have priority.
	// if there are any queued, run them immediately.
	OneShot *oneshot;
	while ((oneshot = r_list_pop_head (core->oneshot_queue))) {
		oneshot->func (oneshot->user);
		free (oneshot);
	}

	RCoreTask *next = r_list_pop_head (core->tasks_queue);

	if (next && !stop) {
		r_list_append (core->tasks_queue, current);
	}

	r_th_lock_leave (core->tasks_lock);

	if (next) {
		r_cons_context_reset ();
		r_th_lock_enter (next->dispatch_lock);
		r_th_cond_signal (next->dispatch_cond);
		r_th_lock_leave (next->dispatch_lock);
		if (!stop) {
			r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
		}
	}

	if (!stop) {
		core->current_task = current;
		if (current->cons_context) {
			r_cons_context_load (current->cons_context);
		} else {
			r_cons_context_reset ();
		}
	} else {
		r_cons_context_reset ();
	}
}

static void task_wakeup(RCoreTask *current) {
	RCore *core = current->core;

	r_th_lock_enter (core->tasks_lock);

	core->tasks_running++;
	current->state = R_CORE_TASK_STATE_RUNNING;

	// check if there are other tasks running
	bool single = core->tasks_running == 1;

	r_th_lock_enter (current->dispatch_lock);

	// if we are not the only task, we must wait until another task signals us.

	if (!single) {
		r_list_append (current->core->tasks_queue, current);
	}

	r_th_lock_leave (core->tasks_lock);

	if(!single) {
		r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
	}

	core->current_task = current;

	if (current->cons_context) {
		r_cons_context_load (current->cons_context);
	} else {
		r_cons_context_reset ();
	}
}

R_API void r_core_task_continue(RCoreTask *t) {
	r_core_task_schedule (t, R_CORE_TASK_STATE_RUNNING);
}

static void task_end(RCoreTask *t) {
	r_core_task_schedule (t, R_CORE_TASK_STATE_DONE);
}

static int task_run(RCoreTask *task) {
	RCore *core = task->core;

	task_wakeup (task);

	char *res_str;
	int res;
	if (task == task->core->main_task) {
		res = r_core_cmd (core, task->cmd, task->cmd_log);
		res_str = NULL;
	} else {
		res = 0;
		res_str = r_core_cmd_str (core, task->cmd);
	}

	if (task->res) {
		free (task->res);
	}
	task->res = res_str;

	if (task != core->main_task) {
		eprintf ("\nTask %d finished\n", task->id);
	}

	task_end (task);

	if (task->cb) {
		task->cb (task->user, task->res);
	}

	if (task->running_sem) {
		r_th_sem_post (task->running_sem);
	}

	return res;
}

static int task_run_thread(RThread *th) {
	return task_run (th->user);
}

R_API void r_core_task_enqueue(RCore *core, RCoreTask *task) {
	if (!core || !task) {
		return;
	}
	r_th_lock_enter (core->tasks_lock);
	if (!task->running_sem) {
		task->running_sem = r_th_sem_new (1);
	}
	if (task->running_sem) {
		r_th_sem_wait (task->running_sem);
	}
	r_list_append (core->tasks, task);
	task->thread = r_th_new (task_run_thread, task, 0);
	r_th_lock_leave (core->tasks_lock);
}

R_API void r_core_task_enqueue_oneshot(RCore *core, RCoreTaskOneShot func, void *user) {
	if (!core || !func) {
		return;
	}
	r_th_lock_enter (core->tasks_lock);
	if (core->tasks_running == 0) {
		// nothing is running right now and no other task can be scheduled
		// while core->tasks_lock is locked => just run it
		func (user);
	} else {
		OneShot *oneshot = R_NEW (OneShot);
		if (oneshot) {
			r_list_append (core->oneshot_queue, oneshot);
		}
	}
	r_th_lock_leave (core->tasks_lock);
}

R_API int r_core_task_run_sync(RCore *core, RCoreTask *task) {
	task->thread = NULL;
	return task_run (task);
}

/* begin running stuff synchronously on the main task */
R_API void r_core_task_sync_begin(RCore *core) {
	RCoreTask *task = core->main_task;
	r_th_lock_enter (core->tasks_lock);
	task->thread = NULL;
	task->cmd = NULL;
	task->cmd_log = false;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	r_th_lock_leave (core->tasks_lock);
	task_wakeup (task);
}

/* end running stuff synchronously, initially started with r_core_task_sync_begin() */
R_API void r_core_task_sync_end(RCore *core) {
	task_end (core->main_task);
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

R_API RCoreTask *r_core_task_self (RCore *core) {
	return core->current_task ? core->current_task : core->main_task;
}

R_API int r_core_task_del (RCore *core, int id) {
	RCoreTask *task;
	RListIter *iter;
	bool ret = false;
	r_th_lock_enter (core->tasks_lock);
	r_list_foreach (core->tasks, iter, task) {
		if (task->id == id) {
			if (task == core->main_task
				|| task->state != R_CORE_TASK_STATE_DONE) {
				break;
			}
			r_list_delete (core->tasks, iter);
			ret = true;
			break;
		}
	}
	r_th_lock_leave (core->tasks_lock);
	return ret;
}

R_API void r_core_task_del_all_done (RCore *core) {
	RCoreTask *task;
	RListIter *iter, *iter2;
	r_list_foreach_safe (core->tasks, iter, iter2, task) {
		if (task != core->main_task && task->state == R_CORE_TASK_STATE_DONE) {
			r_list_delete (core->tasks, iter);
		}
	}
}

R_API RCoreTask *r_core_task_get (RCore *core, int id) {
	RCoreTask *task;
	RListIter *iter;
	r_list_foreach (core->tasks, iter, task) {
		if (task->id == id) {
			return task;
		}
	}
	return NULL;
}
