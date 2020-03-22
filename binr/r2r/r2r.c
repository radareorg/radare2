/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

typedef struct r2r_state_t {
	R2RRunConfig run_config;
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

static int help(bool verbose) {
	printf ("Usage: r2r [test]\n");
	if (verbose) {
		printf (" TODO: verbose help\n");
	}
	return 1;
}

int main(int argc, char **argv) {
	int workers_count = 4; // TODO: read from arg
	int c;
	while ((c = r_getopt (argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			return help (true);
		default:
			return help (false);
		}
	}

	if (!r2r_subprocess_init ()) {
		eprintf ("Subprocess init failed\n");
		return 1;
	}
	atexit (r2r_subprocess_fini);

	R2RState state = { 0 };
	state.run_config.r2_cmd = "radare2";
	state.run_config.rasm2_cmd = "rasm2";
	state.db = r2r_test_database_new ();
	if (!state.db) {
		return 1;
	}
	r_pvector_init (&state.queue, NULL);
	r_pvector_init (&state.results, (RPVectorFree)r2r_test_result_info_free);
	state.lock = r_th_lock_new (false);
	if (!state.lock) {
		return 1;
	}
	state.cond = r_th_cond_new ();
	if (!state.cond) {
		return 1;
	}

	if (optind < argc) {
		// Manually specified path(s)
		int i;
		for (i = optind; i < argc; i++) {
			if (!r2r_test_database_load (state.db, argv[i])) {
				eprintf ("Failed to load tests from \"%s\"\n", argv[i]);
				r2r_test_database_free (state.db);
				return 1;
			}
		}
	} else {
		// Default db path
		if (!r2r_test_database_load (state.db, "db")) {
			eprintf ("Failed to load tests from ./db\n");
			r2r_test_database_free (state.db);
			return 1;
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
			exit (1);
		}
		r_pvector_push (&workers, th);
	}

	ut64 prev_completed = UT64_MAX;
	while (true) {
		ut64 completed = (ut64)r_pvector_len (&state.results);
		if (completed != prev_completed) {
			int w = printf ("\r\x1b[2K[%"PFMT64u"/%"PFMT64u"]", completed, (ut64)r_pvector_len (&state.db->tests));
			while (w >= 0 && w < 20) {
				printf (" ");
				w++;
			}
			printf (" ");
			printf ("OK %8"PFMT64u" BR %8"PFMT64u" XX %8"PFMT64u" FX %8"PFMT64u,
					state.ok_count, state.br_count, state.xx_count, state.fx_count);
			fflush (stdout);
			prev_completed = completed;
		}
		if (completed == r_pvector_len (&state.db->tests)) {
			break;
		}
		r_th_cond_wait (state.cond, state.lock);
	}

	r_th_lock_leave (state.lock);

	void **it;
	r_pvector_foreach (&workers, it) {
		RThread *th = *it;
		r_th_wait (th);
		r_th_free (th);
	}
	r_pvector_clear (&workers);

	r_pvector_clear (&state.queue);
	r_pvector_clear (&state.results);
	r2r_test_database_free (state.db);
	r_th_lock_free (state.lock);
	r_th_cond_free (state.cond);
	return 0;
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

static void run_test(R2RTest *test) {
	R2RTestResultInfo *result = r2r_run_test (NULL, test);
	char *name = r2r_test_name (test);
	printf ("%s: ", name ? name : "");
	switch (result->result) {
		case R2R_TEST_RESULT_OK:
			printf ("OK\n");
			break;
		case R2R_TEST_RESULT_FAILED:
			printf ("XX\n");
			break;
		case R2R_TEST_RESULT_BROKEN:
			printf ("BR\n");
			break;
		case R2R_TEST_RESULT_FIXED:
			printf ("FX\n");
			break;
	}
	r2r_test_result_info_free (result);
	free (name);
}