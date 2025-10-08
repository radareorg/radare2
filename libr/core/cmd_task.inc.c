// Task-related commands extracted from cmd.c
#include <r_core.h>

static int _cmd_tasks_impl(void *data, const char *input) {
	RCore *core = (RCore*) data;
	switch (input[0]) {
	case '\0': // "&" -> list tasks
	case 'j': { // "&j" -> list tasks (json)
		extern void r_core_task_list(RCore *core, int mode);
		r_core_task_list (core, *input);
		break;
	}
	case ':': // "&:"
		r_core_cmd_queue (core, input + 1);
		break;
	case 'w': // "&w"
		r_core_cmd_queue_wait (core);
		break;
	case 'b': { // "&b"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("The &b command is disabled in sandbox mode");
			return 0;
		}
		int tid = r_num_math (core->num, input + 1);
			if (tid) {
				RCoreTask *t = r_core_task_get (&core->tasks, tid);
				if (t) {
					r_core_task_cancel (t, false);
					/* lifetime handled by scheduler */
				}
			}
			break;
		}
	case '&': { // "&&"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("The && command is disabled in sandbox mode");
			return 0;
		}
		int tid = r_num_math (core->num, input + 1);
		r_core_task_join (&core->tasks, core->tasks.current_task, tid ? tid : -1);
		break;
	}
	case '=': { // "&="
		int tid = r_num_math (core->num, input + 1);
		if (tid) {
			RCoreTask *task = r_core_task_get (&core->tasks, tid);
			if (task) {
				if (task->res) {
					r_cons_println (core->cons, task->res);
				}
				/* lifetime handled by scheduler */
			} else {
				R_LOG_ERROR ("Cannot find task");
			}
		}
		break;
	}
	default: { // "& <COMMAND>" -> run command in background task
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("The & command is disabled in sandbox mode");
			return 0;
		}
		const char *cmd = r_str_trim_head_ro (input);
		if (!*cmd) {
			// no subcmd: list tasks
			extern void r_core_task_list(RCore *core, int mode);
			r_core_task_list (core, 0);
			break;
		}
		// schedule command using cooperative mode for backward compatibility; capture output into task->res
		RCoreTask *t = r_core_task_submit (core, cmd, NULL, NULL, true, R_CORE_TASK_MODE_THREAD);
		if (t) {
			int tid = r_core_task_id (t);
			r_cons_printf (core->cons, "[%d] %s\n", tid, cmd);
		}
		break;
	}
	}
	return true;
}

// Export with the original name for the command table
R_IPI int cmd_tasks(void *data, const char *input) {
	return _cmd_tasks_impl (data, input);
}
