/* radare - LGPL - Copyright 2014 - pancake */

#include <r_core.h>

R_API void r_core_task_list (RCore *core, int mode) {
	RListIter *iter;
	RCoreTask *task;
	if (mode=='j') r_cons_printf("[");
	r_list_foreach (core->tasks, iter, task) {
		switch (mode) {
		case 'j':
			r_cons_printf ("{\"id\":%d,\"status\":\"%c\",\"text\":\"%s\"}%s",
				task->id, task->state, task->msg->text, iter->n?",":"");
			break;
		default:
			r_cons_printf ("Task %d Status %c Command %s\n",
					task->id, task->state, task->msg->text);
			if (mode == 1) {
				r_cons_printf ("%s", task->msg->res);
			}
			break;
		}
	}
	if (mode=='j') r_cons_printf("]\n");
}

R_API void r_core_task_join (RCore *core, RCoreTask *task) {
	RListIter *iter;
	if( task) {
		r_cons_break (NULL, NULL);
		r_th_wait (task->msg->th);
		r_cons_break_end ();
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
	if (!task) return NULL;
	task->msg = r_th_msg_new (cmd, r_core_task_thread);
	task->id = r_list_length (core->tasks)+1;
	task->state = 's'; // stopped
	task->core = core;
	task->user = user;
	task->cb = cb;
	return task;
}

R_API void r_core_task_run(RCore *core, RCoreTask *_task) {
	RCoreTask *task;
	RListIter *iter;
	char *str;
	r_list_foreach_prev (core->tasks, iter, task) {
		if (_task && task != _task)
			continue;
		if (task->state!='s')
			continue;
		task->state = 'r'; // running
		str = r_core_cmd_str (core, task->msg->text);
		eprintf ("Task %d finished width %d bytes: %s\n%s\n",
				task->id, (int)strlen (str), task->msg->text, str);
		task->state = 'd'; // done
		task->msg->done = 1; // done DUP!!
		task->msg->res = str;
		if (task->cb) {
			task->cb (task->user, str);
		}
	}
}

R_API void r_core_task_run_bg(RCore *core, RCoreTask *_task) {
	RCoreTask *task;
	RListIter *iter;
	char *str;
	r_list_foreach_prev (core->tasks, iter, task) {
		if (_task && task != _task)
			continue;
		task->state = 'r'; // running
		str = r_core_cmd_str (core, task->msg->text);
		eprintf ("Task %d finished width %d bytes: %s\n%s\n",
				task->id, (int)strlen (str), task->msg->text, str);
		task->state = 'd'; // done
		task->msg->done = 1; // done DUP!!
		task->msg->res = str;
	}
}

R_API RCoreTask *r_core_task_add (RCore *core, RCoreTask *task) {
	//r_th_pipe_push (core->pipe, task->cb, task);
	if (core->tasks) {
		r_list_append (core->tasks, task);
		return task;
	}
	return NULL;
}

R_API void r_core_task_add_bg (RCore *core, RCoreTask *task) {
	//r_th_pipe_push (core->pipe, task->cb, task);
	r_list_append (core->tasks, task);
}

R_API int r_core_task_cat (RCore *core, int id) {
	RCoreTask *task = r_core_task_get (core, id);
	r_cons_printf ("%s\n", task->msg->res);
	r_core_task_del (core, id);
	return R_TRUE;
}

R_API int r_core_task_del (RCore *core, int id) {
	RCoreTask *task;
	RListIter *iter;
	if (id == -1) {
		r_list_free (core->tasks);
		core->tasks = r_list_new ();
		return R_TRUE;
	}
	r_list_foreach (core->tasks, iter, task) {
		if (task->id == id) {
			r_list_delete (core->tasks, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
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
