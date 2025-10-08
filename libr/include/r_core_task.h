#ifndef R2_CORE_TASK_H
#define R2_CORE_TASK_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RCoreTaskCallback)(void *user, char *out);

typedef enum r_core_task_mode_t {
	R_CORE_TASK_MODE_COOP, // Current cooperative model
	R_CORE_TASK_MODE_THREAD, // True threading with isolated core
	R_CORE_TASK_MODE_FORK // Process fork with IPC
} RCoreTaskMode;

typedef enum r_core_task_state_t {
	R_CORE_TASK_STATE_BEFORE_START,
	R_CORE_TASK_STATE_RUNNING,
	R_CORE_TASK_STATE_SLEEPING,
	R_CORE_TASK_STATE_DONE
} RTaskState;

typedef struct r_core_task_t {
	int id;
	RTaskState state;
	bool transient; // delete when finished
	int refcount;
	RThreadSemaphore *running_sem;
	void *user;
	RCore *core;
	// Execution mode and isolation
	RCoreTaskMode mode;
	RCore *task_core; // Isolated core (NULL for cooperative)
	ut64 task_addr; // Per-task address context
	// Thread/fork specific
	RThread *thread; // Thread handle (for thread mode)
	int pid; // Process ID (for fork mode)
	int result_pipe[2]; // Pipe for fork result sync
	// Existing dispatch mechanism
	bool dispatched;
	RThreadCond *dispatch_cond;
	RThreadLock *dispatch_lock;
	// Command and results
	char *cmd;
	char *res;
	bool cmd_log;
	RConsContext *cons_context;
	RCoreTaskCallback cb;
} RCoreTask;

typedef void (*RCoreTaskOneShot)(void *);

typedef struct r_core_tasks_t {
	int task_id_next;
	RList *tasks;
	RList *tasks_queue;
	RList *oneshot_queue;
	int oneshots_enqueued;
	struct r_core_task_t *current_task;
	struct r_core_task_t *main_task;
	RThreadLock *lock;
	int tasks_running;
	bool oneshot_running;
	struct r_core_task_t *foreground_task; // Current ^C target
	RCoreTaskMode default_mode; // Default execution mode
	RCore *main_core; // Reference to main core
} RCoreTaskScheduler;

R_API void r_core_task_scheduler_init(RCoreTaskScheduler *tasks, RCore *core);
R_API void r_core_task_scheduler_fini(RCoreTaskScheduler *tasks);
R_API RCoreTask *r_core_task_get(RCoreTaskScheduler *scheduler, int id);
R_API RCoreTask *r_core_task_get_incref(RCoreTaskScheduler *scheduler, int id);
R_API void r_core_task_print(RCore *core, RCoreTask *task, PJ *pj, int mode);
R_API void r_core_task_list(RCore *core, int mode);
R_API int r_core_task_running_tasks_count(RCoreTaskScheduler *scheduler);
R_API const char *r_core_task_status(RCoreTask *task);
R_API RCoreTask *r_core_task_new(RCore *core, RCoreTaskMode mode, bool create_cons, const char *cmd, RCoreTaskCallback cb, void *user);
R_API void r_core_task_incref(RCoreTask *task);
R_API void r_core_task_decref(RCoreTask *task);
R_API void r_core_task_enqueue(RCoreTaskScheduler *scheduler, RCoreTask *task);
R_API void r_core_task_enqueue_oneshot(RCoreTaskScheduler *scheduler, RCoreTaskOneShot func, void *user);
R_API int r_core_task_run_sync(RCoreTaskScheduler *scheduler, RCoreTask *task);
R_API void r_core_task_sync_begin(RCoreTaskScheduler *scheduler);
R_API void r_core_task_sync_end(RCoreTaskScheduler *scheduler);
R_API void r_core_task_yield(RCoreTaskScheduler *scheduler);
R_API void r_core_task_sleep_begin(RCoreTask *task);
R_API void r_core_task_sleep_end(RCoreTask *task);
R_API void r_core_task_break(RCoreTaskScheduler *scheduler, int id);
R_API void r_core_task_break_all(RCoreTaskScheduler *scheduler);
R_API int r_core_task_del(RCoreTaskScheduler *scheduler, int id);
R_API void r_core_task_del_all_done(RCoreTaskScheduler *scheduler);
R_API RCoreTask *r_core_task_self(RCoreTaskScheduler *scheduler);
R_API void r_core_task_join(RCoreTaskScheduler *scheduler, RCoreTask *current, int id);
// New APIs for threaded task execution
R_API void r_core_task_set_foreground(RCoreTaskScheduler *scheduler, int task_id);
R_API RCoreTask *r_core_task_get_foreground(RCoreTaskScheduler *scheduler);
/* Hidden: task run helpers are internal; use enqueue/new with mode */
R_API void r_core_task_setmode(RCoreTaskScheduler *scheduler, RCoreTaskMode mode);
R_API RCoreTaskMode r_core_task_scheduler_get_default_mode(RCoreTaskScheduler *scheduler);

#ifdef __cplusplus
}
#endif

#endif
