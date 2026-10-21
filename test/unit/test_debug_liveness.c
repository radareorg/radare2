#include <r_debug.h>
#include <signal.h>
#include "minunit.h"

static int kill_calls;
static bool pid_exists;
static RDebugReasonType step_reason;

static bool mock_kill(RDebug *dbg, int pid, int tid, int sig) {
	kill_calls++;
	return pid_exists;
}

static bool mock_step(RDebug *dbg) {
	dbg->reason.type = step_reason;
	return false;
}

static const char *mock_config_get(void *core, const char *key) {
	return NULL;
}

static bool count_step_errors(void *user, int type, const char *origin, const char *msg) {
	if (type == R_LOG_LEVEL_ERROR && msg && strstr (msg, "Stepping failed!")) {
		(*(int *)user)++;
	}
	return true;
}

static RDebugPlugin mock_plugin = {
	.meta = { .name = "liveness-test" },
	.kill = mock_kill,
	.step = mock_step,
};

static RDebugPluginSession mock_session = {
	.plugin = &mock_plugin,
};

static RDebug make_debugger(int pid, RDebugReasonType reason, bool exists) {
	kill_calls = 0;
	pid_exists = exists;
	RDebug dbg = {
		.pid = pid,
		.current = &mock_session,
		.reason = { .type = reason },
	};
	return dbg;
}

bool test_dead_reason_survives_existing_pid(void) {
	RDebug dbg = make_debugger (123, R_DEBUG_REASON_DEAD, true);
	mu_assert_true (r_debug_is_dead (&dbg), "a zombie PID must not override a dead reason");
	mu_assert_eq (kill_calls, 0, "known-dead targets must not be probed");
	mu_assert_eq (dbg.reason.type, R_DEBUG_REASON_DEAD, "retain the dead reason");
	mu_end;
}

bool test_kill_skips_dead_target(void) {
	RDebug dbg = make_debugger (123, R_DEBUG_REASON_DEAD, true);
	mu_assert_false (r_debug_kill (&dbg, 123, 0, SIGTERM), "do not signal a known-dead target");
	mu_assert_eq (kill_calls, 0, "neither probe nor signal a known-dead target");
	mu_end;
}

bool test_live_target_is_probed(void) {
	RDebug dbg = make_debugger (123, R_DEBUG_REASON_BREAKPOINT, true);
	mu_assert_false (r_debug_is_dead (&dbg), "an existing live target is not dead");
	mu_assert_eq (kill_calls, 1, "probe a target without a dead reason");
	mu_assert_eq (dbg.reason.type, R_DEBUG_REASON_BREAKPOINT, "retain a live stop reason");
	mu_end;
}

bool test_missing_target_becomes_dead(void) {
	RDebug dbg = make_debugger (123, R_DEBUG_REASON_UNKNOWN, false);
	mu_assert_true (r_debug_is_dead (&dbg), "a failed PID probe marks the target dead");
	mu_assert_eq (kill_calls, 1, "probe the missing target once");
	mu_assert_eq (dbg.reason.type, R_DEBUG_REASON_DEAD, "record the dead reason");
	mu_end;
}

bool test_negative_pid_is_dead(void) {
	RDebug dbg = make_debugger (-1, R_DEBUG_REASON_UNKNOWN, true);
	mu_assert_true (r_debug_is_dead (&dbg), "a negative native PID is dead");
	mu_assert_eq (kill_calls, 0, "do not probe a negative PID");
	mu_assert_eq (dbg.reason.type, R_DEBUG_REASON_DEAD, "record the dead reason");
	mu_end;
}

bool test_step_exit_is_not_an_error(void) {
	RDebug dbg = make_debugger (123, R_DEBUG_REASON_BREAKPOINT, true);
	dbg.bp = r_bp_new ();
	dbg.coreb.cfgGet = mock_config_get;
	step_reason = R_DEBUG_REASON_DEAD;
	int errors = 0;
	r_log_add_callback (count_step_errors, &errors);
	int steps = r_debug_step (&dbg, 1);
	r_log_del_callback (count_step_errors);
	r_bp_free (dbg.bp);
	mu_assert_eq (steps, 0, "an exit does not complete a step");
	mu_assert_eq (dbg.reason.type, R_DEBUG_REASON_DEAD, "retain the exit reason");
	mu_assert_eq (errors, 0, "an exit during stepping is not a stepping error");
	mu_end;
}

bool test_step_failure_reports_error(void) {
	RDebug dbg = make_debugger (123, R_DEBUG_REASON_BREAKPOINT, true);
	dbg.bp = r_bp_new ();
	dbg.coreb.cfgGet = mock_config_get;
	step_reason = R_DEBUG_REASON_ERROR;
	int errors = 0;
	r_log_add_callback (count_step_errors, &errors);
	int steps = r_debug_step (&dbg, 1);
	r_log_del_callback (count_step_errors);
	r_bp_free (dbg.bp);
	mu_assert_eq (steps, 0, "a failed step does not advance the step count");
	mu_assert_eq (dbg.reason.type, R_DEBUG_REASON_ERROR, "retain the failure reason");
	mu_assert_eq (errors, 1, "a genuine step failure must still report an error");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_dead_reason_survives_existing_pid);
	mu_run_test (test_kill_skips_dead_target);
	mu_run_test (test_live_target_is_probed);
	mu_run_test (test_missing_target_becomes_dead);
	mu_run_test (test_negative_pid_is_dead);
	mu_run_test (test_step_exit_is_not_an_error);
	mu_run_test (test_step_failure_reports_error);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
