Step-by-step implementation plan for RCoreTask redesign

Objective

- Enable true multi-threading and isolation for core tasks
- Make ^C only affect the foreground task
- Support multiple execution modes: cooperative, thread, fork
- Keep changes incremental and safe; start with structural/internal logic and finish with user-facing commands

Phase 1: Structural changes (foundation)

1.1 Update headers
	- Add `RCoreTaskMode` enum (cooperative/thread/fork)
	- Add per-task context fields to `RCoreTask` (mode, task_core, task_addr, pid, result_pipe)
	- Add scheduler fields to `RCoreTaskScheduler` (foreground_task, default_mode, main_core)
	- Add prototypes for new APIs (set/get foreground, run_threaded, run_forked, clone core, scheduler mode setters/getters)
	- Verify headers compile cleanly

1.2 Core initialization
	- In `r_core_task_scheduler_init ()`:
		- create `main_task` (cooperative)
		- set `foreground_task = main_task`
		- set `default_mode = cooperative`
		- store `main_core = core`
	- Add config variable `task.execution_mode` (default: cooperative) in `r_core_config_init ()`

Phase 2: Core logic updates

2.1 Foreground management
	- Implement `r_core_task_set_foreground` and `r_core_task_get_foreground`
	- Ensure scheduler uses `foreground_task` as ^C target

2.2 Signal handling
	- Modify global signal handler to break only `foreground_task->cons_context`
	- Ensure no global context-breaking remains

2.3 Core cloning
	- Implement `r_core_clone_for_task ()` producing a lightweight isolated RCore suitable for tasks
	- Keep resource duplication minimal and safe

Phase 3: Execution modes

3.1 Cooperative mode (backward compatible)
	- Ensure `task_addr` is respected (per-task address context)
	- Minimal changes to existing cooperative scheduler

3.2 Thread mode
	- Implement thread-run path:
		- `r_core_task_run_threaded ()` and `r_core_task_thread_func ()`
		- Use `task->task_core` cloned via `r_core_clone_for_task ()`
		- Signal completion via `running_sem` and set `task->res`

3.3 Fork mode
	- Implement fork-run path:
		- `r_core_task_run_forked ()` and fork child execution
		- Use pipes (`result_pipe`) to send results back
		- Parent waits / reaps child and collects results

3.4 Result synchronization
	- Implement `r_core_task_sync_results ()` to unify collection for thread/fork modes
	- Update `r_core_task_join ()` to handle all modes

Phase 4: Commands and user-facing APIs

4.1 Update `&` commands
	- Show mode, foreground, and `task_addr` in listings
	- Ensure existing break/join/get-result commands operate across modes

4.2 New commands
	- `&f <id>`: set foreground task
	- `&k <id>`: kill/interrupt task
	- `&m <mode> <cmd>`: run command with explicit mode
	- `&c`: show current foreground task
	- `e task.execution_mode = <mode>`: set default mode

Phase 5: Integration and safety

5.1 Dispatch
	- In `r_core_task_enqueue ()`, dispatch the task according to `task->mode` and `scheduler->default_mode`

5.2 Cleanup
	- Extend `task_free ()` to safely clean threads, pipes, cloned cores, cons contexts

5.3 Error handling
	- Add graceful fallbacks for thread/fork failures
	- Prevent unlimited thread/process creation

Phase 6: Advanced features

6.1 Context merging
	- Implement optional `r_core_task_merge_context ()` to selectively apply changes from `task_core` to `main_core`
	- Define what state can be merged (flags, analysis results, aliases) and what cannot (I/O handles)

6.2 Performance
	- Optimize `r_core_clone_for_task ()` (lazy clone, share read-only resources)

Phase 7: Testing & docs

7.1 Unit tests
	- Add unit tests for task creation, mode dispatch, foreground switching, interruption

7.2 Integration tests
	- Update/add `r2r` tests to cover `&` commands, thread/fork behavior, and result collection

7.3 Documentation
	- Update `man/3/r_core.3` and relevant developer docs describing the new APIs and commands

Implementation Guidelines

- Preserve existing indentation and spacing rules (tabs for indent; always a single space before '(' in function calls and macros)
- Make minimal, incremental commits per step (we will do these manually while in build mode)
- Compile after each step (`make -j`) and run `sys/lint.sh` when relevant
- Keep cooperative mode as default for backward compatibility

Notes & Risks

- Cloning `RCore` can be expensive; prefer lightweight clones and lazy copy-on-write where possible
- Merging state back from isolated cores is nontrivial and must be carefully designed (Phase 6)
- Signal handling must be precise: only the `foreground_task` receives ^C

Ready to enter build mode: implement Step 1.2 changes incrementally and run a build after edits.
