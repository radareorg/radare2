#include <r_debug.h>
#include <signal.h>
#include "minunit.h"

static int kill_calls;
static bool pid_exists;

static bool mock_kill(RDebug *dbg, int pid, int tid, int sig) {
	kill_calls++;
	return pid_exists;
}

static RDebugPlugin mock_plugin = {
	.meta = { .name = "liveness-test" },
	.kill = mock_kill,
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

int all_tests(void) {
	mu_run_test (test_dead_reason_survives_existing_pid);
	mu_run_test (test_kill_skips_dead_target);
	mu_run_test (test_live_target_is_probed);
	mu_run_test (test_missing_target_becomes_dead);
	mu_run_test (test_negative_pid_is_dead);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
