/* radare - LGPL - Copyright 2014-2018 - pancake, thestr4ng3r */

#include <r_core.h>

R_API void r_core_task_print (RCore *core, RCoreTask *task, int mode) {
	switch (mode) {
	case 'j':
		r_cons_printf ("{\"id\":%d,\"state\":\"", task->id);
		switch (task->state) {
			case R_CORE_TASK_STATE_BEFORE_START:
				r_cons_print("before_start");
				break;
			case R_CORE_TASK_STATE_RUNNING:
				r_cons_print("running");
				break;
			case R_CORE_TASK_STATE_SLEEPING:
				r_cons_print("sleeping");
				break;
			case R_CORE_TASK_STATE_DONE:
				r_cons_print("done");
				break;
		}
		r_cons_print("\",\"cmd\":");
		if (task->cmd) {
			r_cons_printf("\"%s\"}", task->cmd);
		} else {
			r_cons_printf("null}");
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

R_API void r_core_task_list (RCore *core, int mode) {
	RListIter *iter;
	RCoreTask *task;
	if (mode == 'j') {
		r_cons_printf ("[");
	}
	r_list_foreach (core->tasks, iter, task) {
		r_core_task_print (core, task, mode);
		if (mode == 'j' && iter->n) {
			r_cons_printf (",");
		}
	}
	if (mode == 'j') {
		r_cons_printf ("]\n");
	}
}

R_API void r_core_task_join (RCore *core, RCoreTask *current, RCoreTask *task) {
	RListIter *iter;
	if (current && task == current) {
		return;
	}
	if (task) {
		if (current) {
			r_core_task_sleep_begin (current);
		}
		r_th_wait (task->thread);
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
			r_th_wait (task->thread);
			if (current) {
				r_core_task_sleep_end (current);
			}
		}
	}
}

R_API RCoreTask *r_core_task_new (RCore *core, const char *cmd, RCoreTaskCallback cb, void *user) {
	RCoreTask *task = R_NEW0 (RCoreTask);
	if (!task) {
		goto hell;
	}

	task->thread = NULL;
	task->cmd = cmd ? strdup (cmd) : NULL;
	task->cmd_log = false;
	task->res = NULL;
	task->dispatch_cond = r_th_cond_new ();
	task->dispatch_lock = r_th_lock_new (false);
	if (!task->dispatch_cond || !task->dispatch_lock) {
		goto hell;
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
	r_th_cond_free (task->dispatch_cond);
	r_th_lock_free (task->dispatch_lock);
	r_cons_dump_free (task->cons);
	free (task);
}

R_API void r_core_task_schedule(RCoreTask *current, RTaskState next_state) {
	RCore *core = current->core;
	bool stop = next_state != R_CORE_TASK_STATE_RUNNING;

	core->current_task = NULL;
	
	r_th_lock_enter (core->tasks_lock);

	current->state = next_state;

	if (stop) {
		r_th_lock_leave (current->dispatch_lock);
	}

	RCoreTask *next = r_list_pop_head (core->tasks_queue);

	if (next && !stop) {
		r_list_append (core->tasks_queue, current);
	}

	r_th_lock_leave (core->tasks_lock);

	if (next) {
		current->cons = r_cons_dump ();
		r_th_lock_enter (next->dispatch_lock);
		r_th_cond_signal (next->dispatch_cond);
		r_th_lock_leave (next->dispatch_lock);
		if (!stop) {
			r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
			r_cons_load (current->cons);
			current->cons = NULL;
		}
	} else if (current != core->main_task && stop) {
		// all tasks done, reset to main cons
		current->cons = r_cons_dump ();
		r_cons_load (core->main_task->cons);
		core->main_task->cons = NULL;
	}

	if (!stop) {
		core->current_task = current;
	}
}

static void task_wakeup(RCoreTask *current) {
	RCore *core = current->core;

	r_th_lock_enter (current->core->tasks_lock);

	current->state = R_CORE_TASK_STATE_RUNNING;

	// check if there are other tasks running
	bool single = true;
	RCoreTask *task;
	RListIter *iter;
	r_list_foreach (current->core->tasks, iter, task) {
		if (task != current && task->state == R_CORE_TASK_STATE_RUNNING) {
			single = false;
			break;
		}
	}

	r_th_lock_enter (current->dispatch_lock);

	// if we are not the only task, we must wait until another task signals us.

	if (!single) {
		r_list_append (current->core->tasks_queue, current);
	}

	r_th_lock_leave (current->core->tasks_lock);

	if(!single) {
		r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
	}

	current->core->current_task = current;

	// swap cons
	if (current->cons) {
		// we are the main task and some other task has already dumped the main cons for us
		// or we were sleeping.
		r_cons_load (current->cons);
		current->cons = NULL;
	} if (core->main_task != current) {
		// we are not the main task, so we need a new cons
		current->cons = r_cons_dump_new ();
		if (single) {
			// no other tasks are currently running, so the main cons is currently loaded
			// and has to be dumped.
			core->main_task->cons = r_cons_dump ();
		}
		r_cons_load (current->cons);
		current->cons = NULL;
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

	return res;
}

static int task_run_thread(RThread *th) {
	return task_run (th->user);
}

R_API void r_core_task_enqueue(RCore *core, RCoreTask *task) {
	r_th_lock_enter (core->tasks_lock);
	r_list_append (core->tasks, task);
	task->thread = r_th_new (task_run_thread, task, 0);
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
	task_end(core->main_task);
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
