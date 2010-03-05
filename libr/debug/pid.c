/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>

R_API RDebugPid *r_debug_pid_new(char *path, int pid, char status) {
	RDebugPid *p = R_NEW (RDebugPid);
	p->path = strdup (path);
	p->pid = pid;
	p->status = status;
	p->runnable = R_TRUE;
	return p;
}

R_API RDebugPid *r_debug_pid_free(RDebugPid *pid) {
	//free (pid->path);
	//free (pid);
	return NULL;
}

R_API int r_debug_pid_list(struct r_debug_t *dbg, int pid) {
	RList *list;
	RListIter *iter;
	if (dbg && dbg->h && dbg->h->pids) {
		list = dbg->h->pids (pid);
		if (list == NULL)
			return R_FALSE;
		iter = r_list_iterator (list);
		while (r_list_iter_next (iter)) {
			RDebugPid *p = r_list_iter_get (iter);
			eprintf (" %d %c %s\n", p->pid, p->status, p->path);
		}
		r_list_free (list);
	}
	return R_FALSE;
}

/* processes */
R_API int r_debug_pid_parent(RDebugPid *pid) {
	// fork in child
	return 0;
}

#if 0
R_API int r_debug_pid_del(struct r_debug_t *dbg) {
	// kill da child
	return R_TRUE;
}

/* threads */
R_API int r_debug_pid_add_thread(struct r_debug_t *dbg) {
	// create a thread in process
	return R_TRUE;
}

R_API int r_debug_pid_del_thread(struct r_debug_t *dbg) {
	// kill a thread in process
	return R_TRUE;
}
#endif

/* status */
R_API int r_debug_pid_set_state(struct r_debug_t *dbg, int status) {
	return R_TRUE;
}

/* status */
R_API struct r_debug_pid_t *r_debug_pid_get_status(struct r_debug_t *dbg, int pid) {
	return NULL;
}
