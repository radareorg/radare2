// Task-related commands extracted from cmd.c
#include <r_core.h>

static RCoreHelpMessage help_msg_amper = {
	"Usage:", "&[-|<cmd>]", "Manage tasks (WARNING: Experimental. Use with caution!)",
	"&", "", "list all tasks (alias for 'jobs' command)",
	"&", " <cmd>", "run <cmd> in a new background task (alias for 'bg')",
	"&:", "<cmd>", "queue <cmd> to be executed later when possible",
	"&t", " <cmd>", "run <cmd> in a new transient background task (auto-delete when it is finished)",
	"&j", "", "list all tasks (in JSON)",
	"&=", " 3", "show output of task 3",
	"&b", " 3", "break task 3",
	"&w", "", "wait for queued commands and execute them (^C to end)",
	"&-", " 1", "delete task #1 or schedule for deletion when it is finished",
	"&", "-*", "delete all done tasks",
	"&?", "", "show this help",
	"&&", " 3", "wait until task 3 is finished (alias for 'fg')",
	"&&", "", "wait until all tasks are finished (same as 'fg')",
	NULL
};

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
	case '?': // "&?"
		r_cons_cmd_help (core->cons, help_msg_amper);
		break;
	case 'b': { // "&b"
		if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
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
		if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
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
		if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
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
		// Capture output into task->res.
		RCoreTask *t = r_core_task_new (core, R_CORE_TASK_MODE_THREAD, true, cmd, NULL, NULL);
		if (t) {
			// Flush before the task installs its capture context.
			r_cons_printf (core->cons, "[%d] %s\n", t->id, cmd);
			r_cons_flush (core->cons);
			r_core_task_run_threaded (&core->tasks, t);
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
