/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_debug.h>

R_API RDebugPid *r_debug_pid_new(const char *path, int pid, char status, ut64 pc) {
	RDebugPid *p = R_NEW (RDebugPid);
	p->path = strdup (path);
	p->pid = pid;
	p->status = status;
	p->runnable = R_TRUE;
	p->pc = pc;
	return p;
}

R_API RDebugPid *r_debug_pid_free(RDebugPid *pid) {
	//free (pid->path);
	//free (pid);
	return NULL;
}

R_API RList *r_debug_pids(RDebug *dbg, int pid) {
	if (dbg && dbg->h && dbg->h->pids)
		return dbg->h->pids (pid);
	return NULL;
}

// TODO: deprecate? iterating in api? wtf?
R_API int r_debug_pid_list(struct r_debug_t *dbg, int pid) {
	RList *list;
	RListIter *iter;
	RDebugPid *p;
	if (dbg && dbg->h && dbg->h->pids) {
		list = dbg->h->pids (pid);
		if (list == NULL)
			return R_FALSE;
		r_list_foreach (list, iter, p) {
			eprintf (" %c %d %c %s\n", 
				dbg->pid==p->pid?'*':'-',
				p->pid, p->status, p->path);
		}
		r_list_free (list);
	}
	return R_FALSE;
}

R_API int r_debug_thread_list(struct r_debug_t *dbg, int pid) {
	RList *list;
	RListIter *iter;
	RDebugPid *p;
	if (dbg && dbg->h && dbg->h->pids) {
		list = dbg->h->threads (dbg, pid);
		if (list == NULL)
			return R_FALSE;
		r_list_foreach (list, iter, p) {
			eprintf (" %c %d %c %s\n",
				dbg->tid==p->pid?'*':'-',
				p->pid, p->status, p->path);
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
