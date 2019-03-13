/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_debug.h>

R_API RDebugPid *r_debug_pid_new(const char *path, int pid, int uid, char status, ut64 pc) {
	RDebugPid *p = R_NEW0 (RDebugPid);
	if (!p) {
		return NULL;
	}
	p->path = strdup (path);
	p->pid = pid;
	p->uid = uid;
	p->status = status;
	p->runnable = true;
	p->pc = pc;
	return p;
}

R_API RDebugPid *r_debug_pid_free(RDebugPid *pid) {
	free (pid->path);
	free (pid);
	return NULL;
}

R_API RList *r_debug_pids(RDebug *dbg, int pid) {
	if (dbg && dbg->h && dbg->h->pids) {
		return dbg->h->pids (dbg, pid);
	}
	return NULL;
}

// TODO: deprecate list/iterate functions from core apis? keep them for easiness?
R_API int r_debug_pid_list(RDebug *dbg, int pid, char fmt) {
	RList *list;
	RListIter *iter;
	RDebugPid *p;
	if (dbg && dbg->h && dbg->h->pids) {
		list = dbg->h->pids (dbg, R_MAX (0, pid));
		if (!list) {
			return false;
		}
		if (fmt == 'j') {
			dbg->cb_printf ("[");
		}
		r_list_foreach (list, iter, p) {
			switch (fmt) {
			case 'j':
				dbg->cb_printf ("{\"pid\":%d,"
					"\"uid\":%d,"
					"\"status\":\"%c\","
					"\"path\":\"%s\"}%s",
					p->pid, p->uid, p->status, p->path,
					iter->n?",":"");
				break;
			default:
				dbg->cb_printf (" %c %d uid:%d %c %s\n",
					dbg->pid == p->pid? '*': '-',
					p->pid, p->uid, p->status, p->path);
				break;
			}
		}
		if (fmt == 'j') {
			dbg->cb_printf ("]\n");
		}
		r_list_free (list);
	}
	return false;
}

R_API int r_debug_thread_list(RDebug *dbg, int pid) {
	RList *list;
	RListIter *iter;
	RDebugPid *p;
	if (pid == -1) {
		return false;
	}
	if (dbg && dbg->h && dbg->h->threads) {
		list = dbg->h->threads (dbg, pid);
		if (!list) {
			return false;
		}
		if (pid == -'j') {
			dbg->cb_printf ("[");
			r_list_foreach (list, iter, p) {
				dbg->cb_printf ("{\"pid\":%d,"
						"\"status\":\"%s\","
						"\"path\":\"%s\"}%s",
						p->pid, p->status, p->path,
						iter->n?",":"");
			}
			dbg->cb_printf ("]\n");
		} else {
			r_list_foreach (list, iter, p) {
				dbg->cb_printf (" %c %d %c %s\n",
						dbg->tid == p->pid ? '*' : '-',
						p->pid, p->status, p->path);
			}
		}
		r_list_free (list);
	}
	return false;
}

/* processes */
R_API int r_debug_pid_parent(RDebugPid *pid) {
	// fork in child
	return 0;
}

#if 0
R_API int r_debug_pid_del(struct r_debug_t *dbg) {
	// kill da child
	return true;
}

/* threads */
R_API int r_debug_pid_add_thread(struct r_debug_t *dbg) {
	// create a thread in process
	return true;
}

R_API int r_debug_pid_del_thread(struct r_debug_t *dbg) {
	// kill a thread in process
	return true;
}
#endif

/* status */
R_API int r_debug_pid_set_state(struct r_debug_t *dbg, int status) {
	return true;
}

/* status */
R_API struct r_debug_pid_t *r_debug_pid_get_status(struct r_debug_t *dbg, int pid) {
	return NULL;
}
