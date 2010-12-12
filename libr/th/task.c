/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */
// XXX: Must be implemented
// Launch thread if requested
// Support multiple group of tasks (more than one core f.ex)
//

#include <r_types.h>
#define RTask int

#define MAXTASKS (sizeof (int))

static int tasks;

void int r_task_new(int t, int ) {
	if (tasks & flags)
		return -1;	
	tasks |= flags;
	return flags;
}

R_API int r_task_wait(int t) {
}

R_API int r_task_step(int t) {
	// check and lock if cant continue or stop if cancelled
}

R_API int r_task_stop(int t) {
	
}

R_API int r_task_pause() {
}

R_API int r_task_finish() {
}

R_API int r_task_check() {
}

#ifdef TEST
#define T_FLAGS 1
#define T_SEARCH 2

void task1() {
	RTask t = r_task_new (foo1);
	for (;;) {
		if (!r_task_step (t) && !r_task_wait (t)) {
			r_task_kill (t);
			return;
		}
	}
}

int main() {
	
	return 0;
}
#endif
