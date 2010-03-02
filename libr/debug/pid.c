/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>

R_API int r_debug_pid_list(struct r_debug_t *dbg)
{
	//int count = 0;
	return 0;
}

/* processes */
R_API int r_debug_pid_parent(RDebugPid *pid) {
	// fork in child
	return 0;
}

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

/* status */
R_API int r_debug_pid_set_state(struct r_debug_t *dbg, int status) {
	return R_TRUE;
}

/* status */
R_API struct r_debug_pid_t *r_debug_pid_get_status(struct r_debug_t *dbg, int pid) {
	return NULL;
}
