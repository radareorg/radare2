/* radare - LGPL - Copyright 2014-2018 - pancake */

#include <r_core.h>

R_API void r_core_task_print (RCore *core, RCoreTask *task, int mode) {
	switch (mode) {
	case 'j':
		r_cons_printf ("{\"id\":%d,\"status\":\"%c\",\"text\":\"%s\"}",
				task->id, task->state, task->msg->text);
		break;
	default:
		r_cons_printf ("%2d  %8s  %s\n", task->id, r_core_task_status (task), task->msg->text);
		if (mode == 1) {
			if (task->msg->res) {
				r_cons_println (task->msg->res);
			} else {
				r_cons_newline ();
			}
		}
		break;
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

R_API void r_core_task_join (RCore *core, RCoreTask *task) {
	RListIter *iter;
	if( task) {
		r_cons_break_push (NULL, NULL);
		r_th_wait (task->msg->th);
		r_cons_break_pop ();
	} else {
		r_list_foreach_prev (core->tasks, iter, task) {
			r_th_wait (task->msg->th);
		}
	}
}

static int r_core_task_thread(RCore *core, RCoreTask *task) {
	// TODO
	return 0;
}

R_API RCoreTask *r_core_task_new (RCore *core, const char *cmd, RCoreTaskCallback cb, void *user) {
	RCoreTask *task = R_NEW0 (RCoreTask);
	if (!task) {
		goto hell;
	}

	task->msg = r_th_msg_new (cmd, r_core_task_thread);
	task->dispatch_cond = r_th_cond_new ();
	task->dispatch_lock = r_th_lock_new (false);
	if (!task->msg || !task->dispatch_cond || !task->dispatch_cond) {
		goto hell;
	}

	task->id = core->task_id_next++;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	task->core = core;
	task->user = user;
	task->cb = cb;

	return task;

hell:
	if (task) {
		free (task->msg);
		free (task);
	}
}

static void schedule_tasks(RCoreTask *current, bool end) {
	r_th_lock_enter (current->core->tasks_lock);

	if (end) {
		current->state = R_CORE_TASK_STATE_DONE;
		r_th_lock_leave (current->dispatch_lock);
	}

	RCoreTask *next = r_list_pop_head (current->core->tasks_queue);

	if (next && !end) {
		r_list_append (current->core->tasks_queue, current);
	}

	r_th_lock_leave (current->core->tasks_lock);

	if (next) {
		r_th_lock_enter (next->dispatch_lock);
		r_th_cond_signal (next->dispatch_cond);
		r_th_lock_leave (next->dispatch_lock);
		if (!end) {
			r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
		}
	}
}

static void task_begin(RCoreTask *current) {
	r_th_lock_enter (current->core->tasks_lock);

	current->state = R_CORE_TASK_STATE_RUNNING;

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

	if (!single) {
		r_list_append (current->core->tasks_queue, current);
	}

	r_th_lock_leave (current->core->tasks_lock);

	if(!single) {
		r_th_cond_wait (current->dispatch_cond, current->dispatch_lock);
	}
}

R_API void r_core_task_continue(RCoreTask *t) {
	schedule_tasks(t, false);
}

static void task_end(RCoreTask *t) {
	schedule_tasks(t, true);
}


static int task_finished(void *user, void *data) {
	eprintf ("TASK FINISHED\n");
	return 0;
}

static int task_run(RCoreTask *task) {
	RCore *core = task->core;

	task_begin (task);

	// close (2); // no stderr
	char *res;
	if (task == task->core->main_task) {
		r_core_cmd0 (core, task->msg->text);
		res = NULL;
	} else {
		res = r_core_cmd_str (core, task->msg->text);
	}
	task->msg->res = res;

	eprintf ("\nTask %d finished\n", task->id);

	task_end (task);
	return 0;
}

static int task_run_thread(RThread *th) {
	return task_run (th->user);
}

R_API void r_core_task_enqueue(RCore *core, RCoreTask *task) {
	r_th_lock_enter (core->tasks_lock);
	r_list_append (core->tasks, task);
	task->msg->th = r_th_new (task_run_thread, task, 0);
	r_th_lock_leave (core->tasks_lock);
}

R_API void r_core_task_run_sync(RCore *core, RCoreTask *task) {
	task->msg->th = NULL;
	task_run (task);
}

R_API const char *r_core_task_status (RCoreTask *task) {
	switch (task->state) {
	case R_CORE_TASK_STATE_RUNNING:
		return "running";
	case R_CORE_TASK_STATE_DONE:
		return "done";
	case R_CORE_TASK_STATE_BEFORE_START:
		return "not started yet";
	}
}

R_API RCoreTask *r_core_task_self (RCore *core) {
	RListIter *iter;
	RCoreTask *task;
	R_TH_TID tid = r_th_self ();
	r_list_foreach (core->tasks, iter, task) {
		if (!task || !task->msg || !task->msg->th) {
			continue;
		}
		// TODO: use r_th_equal // pthread_equal
		if (task->msg->th->tid == tid) {
			return task;
		}
	}
	return core->main_task;
}

R_API bool r_core_task_pause (RCore *core, RCoreTask *task, bool enable) {
	if (!core) {
		return false;
	}
	if (task) {
		if (task->state != 'd' && task->msg) {
			r_th_pause (task->msg->th, enable);
		}
	} else {
		RListIter *iter;
		r_list_foreach (core->tasks, iter, task) {
			// XXX: this lock pauses the whole r2
			if (task) {
				r_core_task_pause (core, task, enable);
			}
		}
	}
	return true;
}

R_API int r_core_task_cat (RCore *core, int id) {
	RCoreTask *task = r_core_task_get (core, id);
	r_cons_println (task->msg->res);
	r_core_task_del (core, id);
	return true;
}

R_API int r_core_task_del (RCore *core, int id) {
	RCoreTask *task;
	RListIter *iter;
	if (id == -1) {
		r_list_free (core->tasks);
		core->tasks = r_list_new ();
		return true;
	}
	r_list_foreach (core->tasks, iter, task) {
		if (task->id == id) {
			r_list_delete (core->tasks, iter);
			return true;
		}
	}
	return false;
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
