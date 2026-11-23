#include <r_core.h>
#include "minunit.h"

typedef struct {
	RCons *cons;
	bool expired;
} AnalysisTimeout;

static void expire_analysis_timeout(void *user) {
	AnalysisTimeout *state = user;
	if (state->cons->timeout && !state->expired) {
		// Advance the deadline without depending on the analysis speed.
		state->cons->timeout = r_time_now_mono () - 1;
		state->expired = true;
	}
}

bool test_call_analysis_timeout(void) {
	const char *commands[] = { "aac", "aac*", "aaci", "aaci*" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (commands); i++) {
		RCore *core = r_core_new ();
		r_config_set (core->config, "asm.arch", "x86");
		r_config_set_i (core->config, "asm.bits", 64);
		RIODesc *file = r_core_file_open (core, "malloc://64", R_PERM_RWX, 0);
		mu_assert_notnull (file, "open instruction memory");
		mu_assert_notnull (r_io_map_add (core->io, file->fd, R_PERM_RWX, 0, 0, 64), "map instruction memory");
		ut8 nops[64];
		memset (nops, 0x90, sizeof (nops));
		mu_assert_true (r_io_write_at (core->io, 0, nops, sizeof (nops)), "write instructions without calls");
		r_config_set_i (core->config, "anal.timeout", 1);
		AnalysisTimeout state = { .cons = core->cons };
		core->cons->cb_break = expire_analysis_timeout;
		core->cons->user = &state;
		r_core_cmd0 (core, commands[i]);
		bool expired = state.expired;
		bool interrupted = core->cons->timeout_break;
		bool cleared_deadline = core->cons->timeout == 0;

		r_config_set_i (core->config, "anal.timeout", 0);
		state.expired = false;
		r_cons_break_clear (core->cons);
		r_core_cmd0 (core, commands[i]);
		bool disabled = !state.expired && !core->cons->timeout_break;
		core->cons->cb_break = NULL;
		core->cons->user = NULL;
		r_core_free (core);

		mu_assert_true (expired, "call analysis arms anal.timeout even without discovered functions");
		mu_assert_true (interrupted, "call analysis stops at its deadline");
		mu_assert_true (cleared_deadline, "call analysis does not leak its deadline");
		mu_assert_true (disabled, "call analysis can run again with timeout disabled");
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_call_analysis_timeout);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
