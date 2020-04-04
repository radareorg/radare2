/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"
#include <r_cons.h>

#define WORKERS_DEFAULT        8
#define RADARE2_CMD_DEFAULT    "radare2"
#define RASM2_CMD_DEFAULT      "rasm2"
#define JSON_TEST_FILE_DEFAULT "../bins/elf/crackme0x00b"
#define TIMEOUT_DEFAULT        960

#define STRV(x) #x
#define STR(x) STRV(x)
#define WORKERS_DEFAULT_STR STR(WORKERS_DEFAULT)
#define TIMEOUT_DEFAULT_STR STR(TIMEOUT_DEFAULT)

typedef struct r2r_state_t {
	R2RRunConfig run_config;
	bool verbose;
	R2RTestDatabase *db;

	RThreadCond *cond; // signaled from workers to main thread to update status
	RThreadLock *lock; // protects everything below
	HtPP *path_left; // char * (path to test file) => ut64 * (count of remaining tests)
	RPVector completed_paths;
	ut64 ok_count;
	ut64 xx_count;
	ut64 br_count;
	ut64 fx_count;
	RPVector queue;
	RPVector results;
} R2RState;

static RThreadFunctionRet worker_th(RThread *th);
static void print_state(R2RState *state, ut64 prev_completed);
static void print_log(R2RState *state, ut64 prev_completed, ut64 prev_paths_completed);

static int help(bool verbose) {
	printf ("Usage: r2r [-vh] [-j threads] [test file/dir | @test-type]\n");
	if (verbose) {
		printf (
		" -h           print this help\n"
		" -v           show version\n"
		" -V           verbose\n"
		" -n           do nothing (don't run any test, just load/parse them)\n"
		" -L           log mode (better printing for CI, logfiles, etc.)"
		" -j [threads] how many threads to use for running tests concurrently (default is "WORKERS_DEFAULT_STR")\n"
		" -r [radare2] path to radare2 executable (default is "RADARE2_CMD_DEFAULT")\n"
		" -m [rasm2]   path to rasm2 executable (default is "RASM2_CMD_DEFAULT")\n"
		" -f [file]    file to use for json tests (default is "JSON_TEST_FILE_DEFAULT")\n"
		" -C [dir]     chdir before running r2r (default follows executable symlink + test/new\n"
		" -t [seconds] timeout per test (default is "TIMEOUT_DEFAULT_STR")\n"
		"\n"
		"Supported test types: @json @unit @fuzz @cmds\n"
		"OS/Arch for archos tests: "R2R_ARCH_OS"\n");
	}
	return 1;
}

static void path_left_free_kv(HtPPKv *kv) {
	free (kv->value);
}

static bool r2r_chdir(const char *argv0) {
#if __UNIX__
	if (r_file_is_directory ("db")) {
		return true;
	}
	char src_path[PATH_MAX];
	char *r2r_path = r_file_path (argv0);
	bool found = false;
	if (readlink (r2r_path, src_path, sizeof (src_path)) != -1) {
		char *p = strstr (src_path, R_SYS_DIR "binr"R_SYS_DIR"r2r"R_SYS_DIR"r2r");
		if (p) {
			*p = 0;
			strcat (src_path, R_SYS_DIR"test"R_SYS_DIR"new");
			if (r_file_is_directory (src_path)) {
				(void)chdir (src_path);
				eprintf ("Running from %s\n", src_path);
				found = true;
			}
		}
	}
	free (r2r_path);
	return found;
#else
	return false;
#endif
}

static void r2r_test_run_unit(void) {
	system ("make -C ../unit all run");
}

static bool r2r_chdir_fromtest(const char *test_path) {
	char *abs_test_path = r_file_abspath (test_path);
	if (!r_file_is_directory (abs_test_path)) {
		char *last_slash = (char *)r_str_lchr (abs_test_path, R_SYS_DIR[0]);
		if (last_slash) {
			*last_slash = 0;
		}
	}
	if (chdir (abs_test_path) == -1) {
		return false;
	}
	bool found = false;
	char *cwd = NULL;
	char *old_cwd = NULL;
	while (true) {
		cwd = r_sys_getdir ();
		if (old_cwd && !strcmp (old_cwd, cwd)) {
			break;
		}
		if (r_file_is_directory ("db")) {
			found = true;
			eprintf ("Running from %s\n", cwd);
			break;
		}
		free (old_cwd);
		old_cwd = cwd;
		cwd = NULL;
		if (chdir ("..") == -1) {
			break;
		}
	}
	free (old_cwd);
	free (cwd);
	return found;
}
char *convert_win_cmds (const char *cmds);

int main(int argc, char **argv) {
	int workers_count = WORKERS_DEFAULT;
	bool verbose = false;
	bool nothing = false;
	bool log_mode = false;
	char *radare2_cmd = NULL;
	char *rasm2_cmd = NULL;
	char *json_test_file = NULL;
	const char *r2r_dir = NULL;
	ut64 timeout_sec = TIMEOUT_DEFAULT;
	int ret = 0;

	RGetopt opt;
	r_getopt_init (&opt, argc, (const char **)argv, "hvj:r:m:f:C:LnVt:");

	int c;
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'h':
			ret = help (true);
			goto beach;
		case 'v':
			printf (R2_VERSION "\n");
			return 0;
		case 'V':
			verbose = true;
			break;
		case 'L':
			log_mode = true;
			break;
		case 'j':
			workers_count = atoi (opt.arg);
			if (workers_count <= 0) {
				eprintf ("Invalid thread count\n");
				ret = help (false);
				goto beach;
			}
			break;
		case 'r':
			free (radare2_cmd);
			radare2_cmd = strdup (opt.arg);
			break;
		case 'C':
			r2r_dir = opt.arg;
			break;
		case 'n':
			nothing = true;
			break;
		case 'm':
			free (rasm2_cmd);
			rasm2_cmd = strdup (opt.arg);
			break;
		case 'f':
			free (json_test_file);
			json_test_file = strdup (opt.arg);
			break;
		case 't':
			timeout_sec = strtoull (opt.arg, NULL, 0);
			if (!timeout_sec) {
				timeout_sec = UT64_MAX;
			}
			break;
		default:
			ret = help (false);
			goto beach;
		}
	}

	char *cwd = r_sys_getdir ();
	if (r2r_dir) {
		chdir (r2r_dir);
	} else {
		bool dir_found = (opt.ind < argc && argv[opt.ind][0] != '.')
			? r2r_chdir_fromtest (argv[opt.ind])
			: r2r_chdir (argv[0]);
		if (!dir_found) {
			eprintf ("Cannot find db/ directory related to the given test.\n");
			return -1;

		}
	}

	if (!r2r_subprocess_init ()) {
		eprintf ("Subprocess init failed\n");
		return -1;
	}
	atexit (r2r_subprocess_fini);

	ut64 time_start = r_sys_now ();
	R2RState state = {{0}};
	state.run_config.r2_cmd = radare2_cmd ? radare2_cmd : RADARE2_CMD_DEFAULT;
	state.run_config.rasm2_cmd = rasm2_cmd ? rasm2_cmd : RASM2_CMD_DEFAULT;
	state.run_config.json_test_file = json_test_file ? json_test_file : JSON_TEST_FILE_DEFAULT;
	state.run_config.timeout_ms = timeout_sec > UT64_MAX / 1000 ? UT64_MAX : timeout_sec * 1000;
	state.verbose = verbose;
	state.db = r2r_test_database_new ();
	if (!state.db) {
		return -1;
	}
	r_pvector_init (&state.queue, NULL);
	r_pvector_init (&state.results, (RPVectorFree)r2r_test_result_info_free);
	r_pvector_init (&state.completed_paths, NULL);
	state.lock = r_th_lock_new (false);
	if (!state.lock) {
		return -1;
	}
	state.cond = r_th_cond_new ();
	if (!state.cond) {
		return -1;
	}

	if (opt.ind < argc) {
		// Manually specified path(s)
		int i;
		for (i = opt.ind; i < argc; i++) {
			const char *arg = argv[i];
			if (*arg == '@') {
				arg++;
				eprintf ("Category: %s\n", arg);
				if (!strcmp (arg, "unit")) {
					r2r_test_run_unit ();
					continue;
				} else if (!strcmp (arg, "fuzz")) {
					eprintf (".fuzz: TODO\n");
					continue;
				} else if (!strcmp (arg, "json")) {
					arg = "db/json";
				} else if (!strcmp (arg, "dasm")) {
					arg = "db/asm";
				} else if (!strcmp (arg, "cmds")) {
					arg = "db";
				} else {
					arg = r_str_newf ("db/%s", arg + 1);
				}
			}
			char *tf = (*arg == '/')? strdup (arg)
				: r_str_newf ("%s"R_SYS_DIR"%s", cwd, arg);
			if (!r2r_test_database_load (state.db, tf)) {
				eprintf ("Failed to load tests from \"%s\"\n", tf);
				r2r_test_database_free (state.db);
				free (tf);
				return -1;
			}
			free (tf);
		}
	} else {
		// Default db path
		if (!r2r_test_database_load (state.db, "db")) {
			eprintf ("Failed to load tests from ./db\n");
			r2r_test_database_free (state.db);
			return -1;
		}
	}

	R_FREE (cwd);
	uint32_t loaded_tests = r_pvector_len (&state.db->tests);
	printf ("Loaded %u tests.\n", loaded_tests);
	if (nothing) {
		goto coast;
	}

	bool jq_available = r2r_check_jq_available ();
	if (!jq_available) {
		eprintf ("Skipping json tests because jq is not available.\n");
		size_t i;
		for (i = 0; i < r_pvector_len (&state.db->tests);) {
			R2RTest *test = r_pvector_at (&state.db->tests, i);
			if (test->type == R2R_TEST_TYPE_JSON) {
				r2r_test_free (test);
				r_pvector_remove_at (&state.db->tests, i);
				continue;
			}
			i++;
		}
	}

	r_pvector_insert_range (&state.queue, 0, state.db->tests.v.a, r_pvector_len (&state.db->tests));

	if (log_mode) {
		// Log mode prints the state after every completed file.
		// The count of tests left per file is stored in a ht.
		state.path_left = ht_pp_new (NULL, path_left_free_kv, NULL);
		if (state.path_left) {
			void **it;
			r_pvector_foreach (&state.queue, it) {
				R2RTest *test = *it;
				ut64 *count = ht_pp_find (state.path_left, test->path, NULL);
				if (!count) {
					count = malloc (sizeof (ut64));
					*count = 0;
					ht_pp_insert (state.path_left, test->path, count);
				}
				(*count)++;
			}
		}
	}

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
	ut64 prev_paths_completed = 0;
	while (true) {
		ut64 completed = (ut64)r_pvector_len (&state.results);
		if (log_mode) {
			print_log (&state, prev_completed, prev_paths_completed);
		} else if (completed != prev_completed) {
			print_state (&state, prev_completed);
		}
		prev_completed = completed;
		prev_paths_completed = (ut64)r_pvector_len (&state.completed_paths);
		if (completed == r_pvector_len (&state.db->tests)) {
			break;
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

	if (state.xx_count) {
		ret = 1;
	}

coast:
	r_pvector_clear (&state.queue);
	r_pvector_clear (&state.results);
	r_pvector_clear (&state.completed_paths);
	r2r_test_database_free (state.db);
	r_th_lock_free (state.lock);
	r_th_cond_free (state.cond);
	ut64 seconds = (r_sys_now () - time_start) / 1000000;
	printf ("Finished in");
	if (seconds > 60) {
		ut64 minutes = seconds / 60;
		printf (" %"PFMT64d" minutes and", seconds / 60);
		seconds -= (minutes * 60);
	}
	printf (" %"PFMT64d" seconds.\n", seconds % 60);
beach:
	free (radare2_cmd);
	free (rasm2_cmd);
	free (json_test_file);
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
		if (state->path_left) {
			ut64 *count = ht_pp_find (state->path_left, test->path, NULL);
			if (count) {
				(*count)--;
				if (!*count) {
					r_pvector_push (&state->completed_paths, (void *)test->path);
				}
			}
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

static R2RProcessOutput *print_runner(const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size, void *user) {
	size_t i;
	for (i = 0; i < env_size; i++) {
		printf ("%s=%s ", envvars[i], envvals[i]);
	}
	printf ("%s", file);
	for (i = 0; i < args_size; i++) {
		const char *str = args[i];
		if (strpbrk (str, "\n \'\"")) {
			printf (" '%s'", str); // TODO: escape
		} else {
			printf (" %s", str);
		}
	}
	printf ("\n");
	return NULL;
}

static void print_result_diff(R2RRunConfig *config, R2RTestResultInfo *result) {
	if (result->run_failed) {
		printf (Color_RED "RUN FAILED (e.g. wrong radare2 path)" Color_RESET "\n");
		return;
	}
	switch (result->test->type) {
	case R2R_TEST_TYPE_CMD: {
		r2r_run_cmd_test (config, result->test->cmd_test, print_runner, NULL);
		const char *expect = result->test->cmd_test->expect.value;
		if (expect && strcmp (result->proc_out->out, expect)) {
			printf ("-- stdout\n");
			print_diff (result->proc_out->out, expect);
		}
		expect = result->test->cmd_test->expect_err.value;
		const char *err = result->proc_out->err;
		if (expect && strcmp (err, expect)) {
			printf ("-- stderr\n");
			print_diff (err, expect);
		} else if (*err) {
			printf ("-- stderr\n%s\n", err);
		}
		if (result->proc_out->ret != 0) {
			printf ("-- exit status: "Color_RED"%d"Color_RESET"\n", result->proc_out->ret);
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

static void print_new_results(R2RState *state, ut64 prev_completed) {
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
		if (result->timeout) {
			printf (Color_CYAN" TIMEOUT"Color_RESET);
		}
		printf (" %s "Color_YELLOW"%s"Color_RESET"\n", result->test->path, name);
		if (result->result == R2R_TEST_RESULT_FAILED || (state->verbose && result->result == R2R_TEST_RESULT_BROKEN)) {
			print_result_diff (&state->run_config, result);
		}
		free (name);
	}

}

static void print_state_counts(R2RState *state) {
	printf ("%8"PFMT64u" OK  %8"PFMT64u" BR %8"PFMT64u" XX %8"PFMT64u" FX",
			state->ok_count, state->br_count, state->xx_count, state->fx_count);
}

static void print_state(R2RState *state, ut64 prev_completed) {
	printf (R_CONS_CLEAR_LINE);

	print_new_results (state, prev_completed);

	// [x/x] OK  42 BR  0 ...
	int w = printf ("[%"PFMT64u"/%"PFMT64u"]", (ut64)r_pvector_len (&state->results), (ut64)r_pvector_len (&state->db->tests));
	while (w >= 0 && w < 20) {
		printf (" ");
		w++;
	}
	printf (" ");
	print_state_counts (state);
	fflush (stdout);
}

static void print_log(R2RState *state, ut64 prev_completed, ut64 prev_paths_completed) {
	print_new_results (state, prev_completed);
	ut64 paths_completed = r_pvector_len (&state->completed_paths);
	for (; prev_paths_completed < paths_completed; prev_paths_completed++) {
		printf ("[**] %50s ", (const char *)r_pvector_at (&state->completed_paths, prev_paths_completed));
		print_state_counts (state);
		printf ("\n");
	}
}
