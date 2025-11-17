Task Scheduler API Review (libr/core/task.c)

Scope
- File reviewed: `libr/core/task.c`
- Goal: identify inconsistencies, risky patterns, naming issues, or dead logic that could lead to bugs; recommend concise fixes to keep the API solid and clean.

Findings

1) tasks_running never increments
- Issue: `tasks_running` is decremented in `r_core_task_schedule(stop=true)` but never incremented (the increment code in `task_wakeup` is disabled). As a result, `tasks_running` remains 0.
- Impact: `r_core_task_enqueue_oneshot` always executes oneshots synchronously under the scheduler lock; status reporting via `r_core_task_running_tasks_count` may be misleading.
- Fix: Increment `tasks_running` when a task starts (e.g., in `task_run` before execution) and decrement when finishing. Alternatively, remove `tasks_running` until scheduling semantics are restored.

2) task_wakeup is a no-op
- Issue: Function returns immediately; all scheduling logic inside is `#if 0`-ed out.
- Impact: `r_core_task_sync_begin` and `r_core_task_sleep_end` call `task_wakeup` which does nothing, so no state transitions or queueing occur.
- Fix: Either re-enable minimal wakeup semantics (set state RUNNING; tasks_running++) or remove calls and the dead code; document synchronous mode behaviour explicitly.

3) Incomplete/unused cooperative scheduling paths
- Issue: `tasks_queue`, `dispatched`, `dispatch_cond`, and `dispatch_lock` are only manipulated in `r_core_task_schedule`, but `r_core_task_enqueue` never adds tasks to `tasks_queue` nor sets `state` to RUNNING.
- Impact: `r_core_task_yield`/`schedule` code paths are effectively inert; states rarely reflect reality (tasks often remain "before start" until set to "done").
- Fix: Decide: (a) remove cooperative scheduling remnants for a simpler thread-per-task model, or (b) fully wire them back (enqueue to `tasks_queue`, set RUNNING when dispatching, and use the cond to switch).

4) Executing oneshots while holding the scheduler lock
- Issue: `r_core_task_enqueue_oneshot` calls `func(user)` with `scheduler->lock` held.
- Impact: High risk of deadlocks/re-entrancy issues if the callback touches the scheduler (enqueue/join/del) or other subsystems that may contend on the same lock order.
- Fix: Collect the callback under lock, release the lock, then execute it. Only adjust `oneshots_enqueued` and `oneshot_running` under the lock, not the callback body.

5) Printing under scheduler lock
- Issue: `r_core_task_list` iterates tasks and prints (or generates JSON) while holding `scheduler->lock`.
- Impact: Holding a global lock during I/O may stall other task APIs and creates lock contention; violates short-lock principle.
- Fix: Snapshot tasks under the lock (e.g., clone or collect shallow copies), then unlock and print.

6) task_free assumes fully initialized lock
- Issue: `task_free` unconditionally `r_th_lock_enter(task->dispatch_lock)` even if allocation failed in `r_core_task_new` and `goto hell` calls `task_free`.
- Impact: Possible NULL dereference when `dispatch_lock` (or `dispatch_cond`) is NULL.
- Fix: Guard every resource in `task_free` (check for NULL); acquire `dispatch_lock` only if non-NULL.

7) No thread join/stop on shutdown
- Issue: `r_core_task_scheduler_fini` frees lists/lock but does not join or stop running task threads.
- Impact: Use-after-free hazards if background threads access freed `RCoreTask` or scheduler structures.
- Fix: Before freeing, iterate tasks, request stop/mark transient, join threads, then free. At minimum, join all startable threads or ensure they cannot dereference freed memory.

8) State management inconsistencies
- Issue: Tasks are not marked RUNNING at start; `r_core_task_status` therefore misreports many tasks as "before start" until they are marked DONE in `task_end`.
- Impact: Misleading UI and logic that depends on states.
- Fix: Set `task->state = R_CORE_TASK_STATE_RUNNING` at the start of `task_run` (under lock) and restore consistent transitions.

9) Odd API in r_cons context reset usage
- Issue: `r_core_task_schedule` calls `r_cons_context_reset(current->cons_context)` in the else-branch where `current->cons_context` is NULL.
- Impact: Currently harmless (reset is a no-op), but the call is confusing and suggests misuse of the parameter (reset ignores its argument and uses global state).
- Fix: Replace with explicit `r_cons_context_reset(NULL)` or remove the else-branch with a short comment that no context is present.

10) Running oneshots count drift risk
- Issue: `oneshots_enqueued` is decremented and `oneshot_running` toggled only in `r_core_task_schedule` fast-path. If cooperative scheduling remains disabled, this path may not exercise correctly in all cases.
- Impact: Counters may not reflect real execution status.
- Fix: Centralize oneshot accounting in `r_core_task_enqueue_oneshot` + execution site, independent of other scheduling paths.

11) Potentially blocking JSON/print generation
- Issue: `r_core_task_print` and JSON composition may call into `r_cons` while other threads are active.
- Impact: If future console manager serializes I/O, this is fine; but keep policy to avoid holding scheduler lock around I/O (see 5).
- Fix: Same as 5 — print outside the lock; consider buffering output first.

12) Main task construction not checked
- Issue: `r_core_task_scheduler_init` does not check `main_task` allocation failure.
- Impact: Possible NULL deref down the line.
- Fix: Check `tasks->main_task` and fail/init gracefully.

13) Semantics of running_sem in join
- Observation: `r_core_task_enqueue` waits on `running_sem` and `task_run` posts upon finish; `task_join` does wait+post.
- Risk: Multiple joiners may race; documented behaviour is single waiter. Not a bug per se but should be documented or protected if multi-join is expected.

14) `r_core_task_del` + transient semantics
- Observation: Deleting an active task sets `transient` and it self-removes on completion; this is fine but relies on the thread reaching the epilogue.
- Risk: No immediate cancellation; if desired, document as cooperative cancel only (use `r_core_task_break` when possible).

15) Naming/clarity
- `task_wakeup`: misleading name given it’s a no-op.
- `tasks_queue`: unused in current non-cooperative model; creates confusion.
- `current_task`: only meaningful for legacy scheduling; with TLS in place, prefer TLS and consider removing or limiting usage.

Suggested Minimal Fixes (non-invasive)
- Guard NULLs in `task_free`.
- Mark tasks RUNNING at start of `task_run` under lock; decrement in `task_end`.
- Execute oneshot callbacks outside of `scheduler->lock` (keep accounting under lock).
- Snapshot task list in `r_core_task_list` under lock and print after unlocking.
- Either remove `task_wakeup`/`tasks_queue` paths or wire them consistently; until then, document that cooperative scheduling is disabled.
- Add a shutdown path in `r_core_task_scheduler_fini` to wait/join active task threads.

Notes
- TLS (implemented) improves correctness for `r_core_task_self` and is compatible with these cleanups.
- Changes should be incremental to avoid destabilizing existing behaviour.

