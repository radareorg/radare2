/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#include <r_cons.h>

typedef struct r2r_state_t {
	R2RRunConfig run_config;
	bool verbose;
	R2RTestDatabase *db;

	RThreadCond *cond; // signaled from workers to main thread to update status
	RThreadLock *lock; // protects everything below
	ut64 ok_count;
	ut64 xx_count;
	ut64 br_count;
	ut64 fx_count;
	RPVector queue;
	RPVector results;
} R2RState;

static RThreadFunctionRet worker_th(RThread *th);
static void print_state(R2RState *state, ut64 prev_completed);

static int help(bool verbose) {
	printf ("Usage: r2r [test]\n");
	if (verbose) {
		printf (" TODO: verbose help\n");
	}
	return 1;
}

int main(int argc, char **argv) {
	int workers_count = 4; // TODO: read from arg
	bool verbose = false;
	int c;
	while ((c = r_getopt (argc, argv, "hv")) != -1) {
		switch (c) {
		case 'h':
			return help (true);
		case 'v':
			verbose = true;
			break;
		default:
			return help (false);
		}
	}

	if (!r2r_subprocess_init ()) {
		eprintf ("Subprocess init failed\n");
		return -1;
	}
	atexit (r2r_subprocess_fini);

	R2RState state = {{0}};
	state.run_config.r2_cmd = "radare2";
	state.run_config.rasm2_cmd = "rasm2";
	state.verbose = verbose;
	state.db = r2r_test_database_new ();
	if (!state.db) {
		return -1;
	}
	r_pvector_init (&state.queue, NULL);
	r_pvector_init (&state.results, (RPVectorFree)r2r_test_result_info_free);
	state.lock = r_th_lock_new (false);
	if (!state.lock) {
		return -1;
	}
	state.cond = r_th_cond_new ();
	if (!state.cond) {
		return -1;
	}

	if (r_optind < argc) {
		// Manually specified path(s)
		int i;
		for (i = r_optind; i < argc; i++) {
			if (!r2r_test_database_load (state.db, argv[i])) {
				eprintf ("Failed to load tests from \"%s\"\n", argv[i]);
				r2r_test_database_free (state.db);
				return -1;
			}
		}
	} else {
		// Default db path
		if (!r2r_test_database_load (state.db, "db")) {
			eprintf ("Failed to load tests from ./db\n");
			r2r_test_database_free (state.db);
			return -1;
		}
	}

	r_pvector_insert_range (&state.queue, 0, state.db->tests.v.a, r_pvector_len (&state.db->tests));

	r_th_lock_enter (state.lock);

	RPVector workers;
	r_pvector_init (&workers, NULL);
	int i;
	for (i = 0; i < workers_count; i++) {
		RThread *th = r_th_new (worker_th, &state, 0);
		if (!th) {
			eprintf ("Failed to start thread.\n");
			exit (-1);
		}
		r_pvector_push (&workers, th);
	}

	ut64 prev_completed = UT64_MAX;
	while (true) {
		ut64 completed = (ut64)r_pvector_len (&state.results);
		if (completed != prev_completed) {
			print_state (&state, prev_completed);
			prev_completed = completed;
			if (completed == r_pvector_len (&state.db->tests)) {
				break;
			}
		}
		r_th_cond_wait (state.cond, state.lock);
	}

	r_th_lock_leave (state.lock);

	printf ("\n");

	void **it;
	r_pvector_foreach (&workers, it) {
		RThread *th = *it;
		r_th_wait (th);
		r_th_free (th);
	}
	r_pvector_clear (&workers);

	int ret = 0;
	if (state.xx_count) {
		ret = 1;
	}

	r_pvector_clear (&state.queue);
	r_pvector_clear (&state.results);
	r2r_test_database_free (state.db);
	r_th_lock_free (state.lock);
	r_th_cond_free (state.cond);
	return ret;
}

static RThreadFunctionRet worker_th(RThread *th) {
	R2RState *state = th->user;
	r_th_lock_enter (state->lock);
	while (true) {
		if (r_pvector_empty (&state->queue)) {
			break;
		}
		R2RTest *test = r_pvector_pop (&state->queue);
		r_th_lock_leave (state->lock);

		R2RTestResultInfo *result = r2r_run_test (&state->run_config, test);

		r_th_lock_enter (state->lock);
		r_pvector_push (&state->results, result);
		switch (result->result) {
		case R2R_TEST_RESULT_OK:
			state->ok_count++;
			break;
		case R2R_TEST_RESULT_FAILED:
			state->xx_count++;
			break;
		case R2R_TEST_RESULT_BROKEN:
			state->br_count++;
			break;
		case R2R_TEST_RESULT_FIXED:
			state->fx_count++;
			break;
		}
		r_th_cond_signal (state->cond);
	}
	r_th_lock_leave (state->lock);
	return R_TH_STOP;
}

static void print_diff(const char *actual, const char *expected) {
#define DO_DIFF !__WINDOWS__
#if DO_DIFF
	RDiff *d = r_diff_new ();
	char *uni = r_diff_buffers_to_string (d, (const ut8 *)expected, (int)strlen (expected), (const ut8 *)actual, (int)strlen (actual));
	r_diff_free (d);

	RList *lines = r_str_split_duplist (uni, "\n");
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
		char c = *line;
		switch (c) {
		case '+':
			printf ("%s", Color_GREEN);
			break;
		case '-':
			printf ("%s", Color_RED);
			break;
		default:
			break;
		}
		printf ("%s\n", line);
		if (c == '+' || c == '-') {
			printf ("%s", Color_RESET);
		}
	}
	r_list_free (lines);
	free (uni);
	printf ("\n");
#else
	RList *lines = r_str_split_duplist (expected, "\n");
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
		printf (Color_RED"- %s"Color_RESET"\n", line);
	}
	r_list_free (lines);
	lines = r_str_split_duplist (actual, "\n");
	r_list_foreach (lines, it, line) {
		printf (Color_GREEN"+ %s"Color_RESET"\n", line);
	}
	r_list_free (lines);
#endif
}

static void print_result_diff(R2RTestResultInfo *result) {
	switch (result->test->type) {
	case R2R_TEST_TYPE_CMD: {
		const char *expect = result->test->cmd_test->expect.value;
		if (!expect) {
			expect = "";
		}
		if (strcmp (result->proc_out->out, expect) != 0) {
			printf ("-- stdout\n");
			print_diff (result->proc_out->out, expect);
		}
		expect = result->test->cmd_test->expect_err.value;
		if (!expect) {
			break;
		}
		if (strcmp (result->proc_out->err, expect) != 0) {
			printf ("-- stderr\n");
			print_diff (result->proc_out->err, expect);
		}
		break;
	}
	case R2R_TEST_TYPE_ASM:
		// TODO
		break;
	case R2R_TEST_TYPE_JSON:
		break;
	}
}

static void print_state(R2RState *state, ut64 prev_completed) {
	printf (R_CONS_CLEAR_LINE);

	// Detailed test result (with diff if necessary)
	ut64 completed = (ut64)r_pvector_len (&state->results);
	ut64 i;
	for (i = prev_completed; i < completed; i++) {
		R2RTestResultInfo *result = r_pvector_at (&state->results, (size_t)i);
		if (!state->verbose && (result->result == R2R_TEST_RESULT_OK || result->result == R2R_TEST_RESULT_FIXED || result->result == R2R_TEST_RESULT_BROKEN)) {
			continue;
		}
		char *name = r2r_test_name (result->test);
		if (!name) {
			continue;
		}
		switch (result->result) {
		case R2R_TEST_RESULT_OK:
			printf (Color_GREEN"[OK]"Color_RESET);
			break;
		case R2R_TEST_RESULT_FAILED:
			printf (Color_RED"[XX]"Color_RESET);
			break;
		case R2R_TEST_RESULT_BROKEN:
			printf (Color_BLUE"[BR]"Color_RESET);
			break;
		case R2R_TEST_RESULT_FIXED:
			printf (Color_CYAN"[FX]"Color_RESET);
			break;
		}
		printf (" %s "Color_YELLOW"%s"Color_RESET"\n", result->test->path, name);
		if (result->result == R2R_TEST_RESULT_FAILED || (state->verbose && result->result == R2R_TEST_RESULT_BROKEN)) {
			print_result_diff (result);
		}
		free (name);
	}

	// [x/x] OK  42 BR  0 ...
	int w = printf ("[%"PFMT64u"/%"PFMT64u"]", completed, (ut64)r_pvector_len (&state->db->tests));
	while (w >= 0 && w < 20) {
		printf (" ");
		w++;
	}
	printf (" ");
	printf ("OK %8"PFMT64u" BR %8"PFMT64u" XX %8"PFMT64u" FX %8"PFMT64u,
			state->ok_count, state->br_count, state->xx_count, state->fx_count);
	fflush (stdout);
}
