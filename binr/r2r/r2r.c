/* radare - LGPL - Copyright 2020-2025 - pancake, thestr4ng3r */

#include "r2r.h"
#if ALLINC
#include "load.c"
#include "run.c"
#endif

#define WORKERS_DEFAULT 8
#define JSON_TEST_FILE_DEFAULT "bins/elf/crackme0x00b"
// 30 seconds is the maximum time a test can run -- not enough for asan builds
#define TIMEOUT_DEFAULT (60 * 60)

#define STRV(x) #x
#define STR(x) STRV(x)
#define WORKERS_DEFAULT_STR STR(WORKERS_DEFAULT)
#define TIMEOUT_DEFAULT_STR STR(TIMEOUT_DEFAULT)

typedef struct r2r_state_t {
	R2RRunConfig run_config;
	bool verbose;
	bool quiet;
	R2RTestDatabase *db;
	PJ *test_results;

	RThreadCond *cond; // signaled from workers to main thread to update status
	RThreadLock *lock; // protects everything below
	HtPP *path_left; // char *(path to test file) => ut64 *(count of remaining tests)
	RVecConstCharPtr completed_paths;
	ut64 counters[4]; // indexed by R2RTestResult: OK, FAILED, BROKEN, FIXED
	ut64 sk_count;
	RVecR2RTestPtr queue;
	RVecR2RTestResultInfoPtr results;
} R2RState;

typedef struct r2r_options_t {
	int workers_count;
	bool verbose;
	bool nothing;
	bool quiet;
	bool log_mode;
	bool interactive;
	bool get_bins;
	int shallow;
	ut64 timeout_sec;
	char *json_test_file;
	char *output_file;
	char *fuzz_dir;
	const char *r2r_dir;
} R2ROptions;

static RThreadFunctionRet worker_th(RThread *th);
/* Mutex to serialize multi-line failure printing across threads */
static RThreadLock *r2r_print_lock = NULL;
static void print_state(R2RState *state, ut64 prev_completed);
static void print_log(R2RState *state, ut64 prev_completed, ut64 prev_paths_completed);
static void interact(R2RState *state);
static void r2r_git(void);
static void interact_fix(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results);
static void interact_break(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results);
static void interact_commands(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results);
static void interact_diffchar(R2RTestResultInfo *result);
static void results_clear(RVecR2RTestResultInfoPtr *vec);

R_IPI const char *getarchos(void) {
	if (R_SYS_BITS_CHECK (R_SYS_BITS, 64)) {
		return R_SYS_OS "-" R_SYS_ARCH "_64";
	}
	if (R_SYS_BITS_CHECK (R_SYS_BITS, 32)) {
		return R_SYS_OS "-" R_SYS_ARCH "_32";
	}
	return R_SYS_OS "-" R_SYS_ARCH;
}

static void results_clear(RVecR2RTestResultInfoPtr *vec) {
	R2RTestResultInfo **it;
	R_VEC_FOREACH (vec, it) {
		r2r_test_result_info_free (*it);
	}
	RVecR2RTestResultInfoPtr_fini (vec);
}

static void parse_skip(const char *arg) {
	if (strstr (arg, "arch")) {
		r_sys_setenv ("R2R_SKIP_ARCHOS", "1");
	} else if (strstr (arg, "unit")) {
		r_sys_setenv ("R2R_SKIP_UNIT", "1");
	} else if (strstr (arg, "cmd")) {
		r_sys_setenv ("R2R_SKIP_CMD", "1");
	} else if (strstr (arg, "fuzz")) {
		r_sys_setenv ("R2R_SKIP_FUZZ", "1");
	} else if (strstr (arg, "json")) {
		r_sys_setenv ("R2R_SKIP_JSON", "1");
	} else if (strstr (arg, "asm")) {
		r_sys_setenv ("R2R_SKIP_ASM", "1");
	} else {
		R_LOG_ERROR ("Invalid -s argument: @arch @unit @cmd @fuzz @json @asm");
	}
}

static void helpvars(int workers_count) {
	printf (
		"R2R_SKIP_ARCHOS=0  # do not run the arch-os-specific tests\n"
		"R2R_SKIP_JSON=0    # do not run the JSON tests\n"
		"R2R_SKIP_FUZZ=0    # do not run the fuzz tests\n"
		"R2R_SKIP_UNIT=0    # do not run the unit tests\n"
		"R2R_SKIP_CMD=0     # do not run the cmds tests\n"
		"R2R_SKIP_ASM=0     # do not run the rasm2 tests\n"
		"R2R_JOBS=%d         # maximum parallel jobs\n"
		"R2R_TIMEOUT=%d   # timeout after 1 minute (60 * 60)\n"
		"R2R_OFFLINE=0      # same as passing -u\n"
		"R2R_SHALLOW=0      # skip 0-100%% random tests\n"
		"R2R_RADARE2=radare2 # radare2 binary to launch\n",
		workers_count, TIMEOUT_DEFAULT);
}

static int help(bool verbose, int workers_count) {
	printf ("Usage: r2r [-qvVnLi] [-C dir] [-F dir] [-f file] [-o file] [-s test] [-t seconds] [-j threads] [test file/dir | @test-type]\n");
	if (verbose) {
		printf (
			" -C [dir]     chdir before running r2r (default follows executable symlink + test/new\n"
			" -F [dir]     run fuzz tests (open and default analysis) on all files in the given dir\n"
			" -L           log mode (better printing for CI, logfiles, etc.)\n"
			" -V           verbose\n"
			" -f [file]    file to use for json tests (default is " JSON_TEST_FILE_DEFAULT ")\n"
			" -g           run the tests specified via '// R2R' comments in modified source files\n"
			" -h           print this help\n"
			" -H           display environment variables\n"
			" -i           interactive mode\n"
			" -j [threads] how many threads to use for running tests concurrently (default is " WORKERS_DEFAULT_STR ")\n"
			" -n           do nothing (don't run any test, just load/parse them)\n"
			" -o [file]    output test run information in JSON format to file\n"
			" -q           quiet\n"
			" -s [test]    set R2R_SKIP_(TEST)=1 to skip running that test type\n"
			" -S [0-100]   set R2R_SHALLOW=N to skip a random percentage of tests\n"
			" -t [seconds] timeout per test (default is " TIMEOUT_DEFAULT_STR ")\n"
			" -u           do not git pull/clone test/bins (See R2R_OFFLINE)\n"
			" -v           show version\n"
			"\n");
		helpvars (workers_count);
		printf ("\n"
		"Supported test types: @asm @json @unit @fuzz @arch @cmd\n"
		"OS/Arch for archos tests: %s\n",
			getarchos ());
	}
	return 1;
}

static void path_left_free_kv(HtPPKv *kv) {
	free (kv->value);
}

static bool r2r_chdir(const char *argv0) {
#if R2__UNIX__
	if (r_file_is_directory ("db")) {
		return true;
	}
	char *src_path = malloc (PATH_MAX);
	if (!src_path) {
		return false;
	}
	char *r2r_path = r_file_path (argv0);
	if (!r2r_path) {
		free (src_path);
		return false;
	}
	bool found = false;
	if (readlink (r2r_path, src_path, PATH_MAX) != -1) {
		src_path[PATH_MAX - 1] = 0;
		char *p = strstr (src_path, "/binr/r2r/r2r");
		if (p) {
			*p = 0;
			src_path = r_str_append (src_path, "/test/");
			if (r_file_is_directory (src_path)) {
				if (chdir (src_path) != -1) {
					R_LOG_INFO ("Running from %s", src_path);
					found = true;
				} else {
					R_LOG_ERROR ("Cannot find '%s' directory", src_path);
				}
			}
		}
	}
	free (src_path);
	free (r2r_path);
	return found;
#else
	return false;
#endif
}

static bool r2r_test_run_unit(void) {
	char *make = r_file_path ("gmake");
	if (!make) {
		make = r_file_path ("make");
		if (!make) {
			R_LOG_ERROR ("Cannot find `make` in PATH");
			return false;
		}
	}
	char *cmd = r_str_newf ("%s -C unit run", make);
	int rc = r_sandbox_system (cmd, 1) == 0;
	free (cmd);
	free (make);
	return rc == 0;
}

static bool r2r_chdir_fromtest(const char *test_path) {
	if (*test_path == '@') {
		test_path = "";
	}
	char *abs_test_path = r_file_abspath (test_path);
	if (!r_file_is_directory (abs_test_path)) {
		char *last_slash = (char *)r_str_lchr (abs_test_path, R_SYS_DIR[0]);
		if (last_slash) {
			*last_slash = 0;
		}
	}
	if (chdir (abs_test_path) == -1) {
		free (abs_test_path);
		return false;
	}
	free (abs_test_path);
	bool found = false;
	char *cwd = NULL;
	char *old_cwd = NULL;
	while (true) {
		cwd = r_sys_getdir ();
		if (old_cwd && !strcmp (old_cwd, cwd)) {
			break;
		}
		if (r_file_is_directory ("test")) {
			if (!r_sys_chdir ("test")) {
				R_LOG_ERROR ("Cannot enter into the 'test' directory");
				break;
			}
			if (r_file_is_directory ("db")) {
				found = true;
				R_LOG_INFO ("Running from %s", cwd);
				break;
			}
			if (!r_sys_chdir ("..")) {
				R_LOG_ERROR ("Cannot up one directory");
				break;
			}
		}
		if (r_file_is_directory ("db")) {
			found = true;
			R_LOG_INFO ("Running from %s", cwd);
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

static void r2r_from_sourcecomments(RList *list, const char *path) {
	const char bait[] = "// R2R ";
	char *s = r_file_slurp (path, NULL);
	if (s) {
		char *p = s;
		while (p) {
			char *r2r = strstr (p, bait);
			if (!r2r) {
				break;
			}
			r2r += strlen (bait);
			if (*r2r != '"') {
				char *nl = strchr (r2r, '\n');
				if (nl) {
					*nl = 0;
					p = nl + 1;
				}
				char *tests = strdup (r2r);
				int i, items = r_str_split (tests, ' ');
				char *test = tests;
				for (i = 0; i < items; i++) {
					r_list_append (list, strdup (test));
					test += strlen (test) + 1;
				}
				free (tests);
			} else {
				p = r2r + strlen (bait);
			}
		}
		free (s);
	} else {
		R_LOG_WARN ("Cannot open %s", path);
	}
}

static R2ROptions r2r_options_init(void) {
	R2ROptions opt = { 0 };
	opt.workers_count = WORKERS_DEFAULT;
	opt.timeout_sec = TIMEOUT_DEFAULT;
	opt.get_bins = !r_sys_getenv_asbool ("R2R_OFFLINE");
	opt.shallow = r_sys_getenv_asut64 ("R2R_SHALLOW");

	char *r2r_timeout = r_sys_getenv ("R2R_TIMEOUT");
	if (R_STR_ISNOTEMPTY (r2r_timeout)) {
		opt.timeout_sec = r_num_math (NULL, r2r_timeout);
	}
	free (r2r_timeout);

	ut64 r2r_jobs = r_sys_getenv_asut64 ("R2R_JOBS");
	if (r2r_jobs > 0) {
		opt.workers_count = r2r_jobs;
	}
	return opt;
}

static void r2r_options_fini(R2ROptions *opt) {
	free (opt->json_test_file);
	free (opt->output_file);
	free (opt->fuzz_dir);
}

// Returns: >= 0 = arg index to continue from, -1 = exit with success, -2 = exit with error
static int r2r_parse_args(R2ROptions *opt, int argc, char **argv) {
	RGetopt go;
	r_getopt_init (&go, argc, (const char **)argv, "hqvj:r:m:f:C:LnVt:F:io:s:ugHS:");

	int c;
	while ((c = r_getopt_next (&go)) != -1) {
		switch (c) {
		case 'g':
			r2r_git ();
			return -1;
		case 'h':
			help (true, opt->workers_count);
			return -1;
		case 'q':
			opt->quiet = true;
			r_log_set_quiet (true);
			break;
		case 'v':
			if (opt->quiet) {
				printf (R2_VERSION "\n");
			} else {
				char *s = r_str_version ("r2r");
				if (s) {
					printf ("%s\n", s);
					free (s);
				}
			}
			return -1;
		case 'V':
			opt->verbose = true;
			break;
		case 'i':
			opt->interactive = true;
			break;
		case 'L':
			opt->log_mode = true;
			break;
		case 's':
			parse_skip (go.arg);
			break;
		case 'S':
			opt->shallow = atoi (go.arg);
			r_sys_setenv_asut64 ("R2R_SHALLOW", opt->shallow);
			break;
		case 'F':
			free (opt->fuzz_dir);
			opt->fuzz_dir = strdup (go.arg);
			break;
		case 'j':
			opt->workers_count = atoi (go.arg);
			if (opt->workers_count <= 0) {
				R_LOG_ERROR ("Invalid thread count");
				help (false, opt->workers_count);
				return -2;
			}
			break;
		case 'C':
			opt->r2r_dir = go.arg;
			break;
		case 'n':
			opt->nothing = true;
			break;
		case 'f':
			free (opt->json_test_file);
			opt->json_test_file = strdup (go.arg);
			break;
		case 'H':
			helpvars (opt->workers_count);
			return -1;
		case 'u':
			opt->get_bins = false;
			break;
		case 't':
			opt->timeout_sec = r_num_math (NULL, go.arg);
			if (!opt->timeout_sec) {
				opt->timeout_sec = UT64_MAX;
			}
			break;
		case 'o':
			free (opt->output_file);
			opt->output_file = r_file_abspath (go.arg);
			break;
		default:
			help (false, opt->workers_count);
			return -2;
		}
	}
	return go.ind;
}

static bool r2r_setup_directory(R2ROptions *opt, int arg_ind, int argc, char **argv, char **cwd_out) {
	char *cwd = r_sys_getdir ();
	*cwd_out = cwd;

	if (opt->r2r_dir) {
		if (chdir (opt->r2r_dir) == -1) {
			R_LOG_ERROR ("Cannot find %s directory", opt->r2r_dir);
			return false;
		}
		return true;
	}

	bool dir_found = false;
	if (arg_ind < argc) {
		const char *avi = argv[arg_ind];
		if (!strcmp (avi, ".")) {
			avi = cwd;
			argv[arg_ind] = cwd;
		}
		dir_found = (avi[0] != '.' || (*avi && !avi[1]))
			? r2r_chdir_fromtest (avi)
			: r2r_chdir (argv[0]);
	} else {
		dir_found = r2r_chdir (argv[0]);
	}

	if (!dir_found) {
		R_LOG_ERROR ("Cannot find db/ directory related to the given test");
		return false;
	}
	return true;
}

static void r2r_setup_environment(void) {
	if (!r_sys_getenv ("R2_BIN")) {
		r_sys_setenv ("R2_BIN", R2_BINDIR);
		r_sys_setenv_sep ("PATH", R2_BINDIR, false);
	}
	char *have_options = r_sys_getenv ("ASAN_OPTIONS");
	if (have_options) {
		free (have_options);
	} else {
		r_sys_setenv ("ASAN_OPTIONS", "detect_leaks=false detect_odr_violation=0");
	}
	r_sys_setenv ("RABIN2_TRYLIB", "0");
	r_sys_setenv ("R2_DEBUG_ASSERT", "1");
	r_sys_setenv ("R2_DEBUG_EPRINT", "0");
	r_sys_setenv ("TZ", "UTC");
}

static bool r2r_state_init(R2RState *state, R2ROptions *opt) {
	memset (state, 0, sizeof (R2RState));

	if (opt->shallow > 0) {
		r_num_irand ();
		state->run_config.shallow = opt->shallow;
	}

	char *r2_binary = r_sys_getenv ("R2R_RADARE2");
	if (R_STR_ISNOTEMPTY (r2_binary)) {
		R_LOG_INFO ("Using custom r2 binary: %s", r2_binary);
		state->run_config.r2_cmd = r2_binary;
	} else {
		free (r2_binary);
		state->run_config.r2_cmd = "radare2";
	}
	state->run_config.skip_cmd = r_sys_getenv_asbool ("R2R_SKIP_CMD");
	state->run_config.skip_asm = r_sys_getenv_asbool ("R2R_SKIP_ASM");
	state->run_config.skip_json = r_sys_getenv_asbool ("R2R_SKIP_JSON");
	state->run_config.skip_fuzz = r_sys_getenv_asbool ("R2R_SKIP_FUZZ");
	state->run_config.rasm2_cmd = "rasm2";
	state->run_config.json_test_file = opt->json_test_file? opt->json_test_file: JSON_TEST_FILE_DEFAULT;
	state->run_config.timeout_ms = (opt->timeout_sec > UT64_MAX / 1000)? UT64_MAX: opt->timeout_sec * 1000;
	state->verbose = opt->verbose;
	state->quiet = opt->quiet;

	state->db = r2r_test_database_new ();
	if (!state->db) {
		return false;
	}

	RVecR2RTestPtr_init (&state->queue);
	RVecR2RTestResultInfoPtr_init (&state->results);
	RVecConstCharPtr_init (&state->completed_paths);

	if (opt->output_file) {
		state->test_results = pj_new ();
		pj_a (state->test_results);
	}

	state->lock = r_th_lock_new (false);
	if (!state->lock) {
		return false;
	}
	state->cond = r_th_cond_new ();
	if (!state->cond) {
		return false;
	}

	return true;
}

static void r2r_state_fini(R2RState *state) {
	RVecR2RTestPtr_fini (&state->queue);
	results_clear (&state->results);
	RVecConstCharPtr_fini (&state->completed_paths);
	r2r_test_database_free (state->db);
	ht_pp_free (state->path_left);
	r_th_lock_free (state->lock);
	r_th_cond_free (state->cond);
}

// Returns: 0 = success, -1 = error, 1 = special exit (e.g., .c file handling)
static int r2r_load_tests(R2RState *state, R2ROptions *opt, int arg_ind, int argc, char **argv, char *cwd, bool skip_json_tests) {
	if (arg_ind < argc) {
		int i;
		for (i = arg_ind; i < argc; i++) {
			const char *arg = argv[i];
			if (*arg == '@') {
				arg++;
				eprintf ("Category: %s\n", arg);
				if (!strcmp (arg, "unit")) {
					if (!r2r_test_run_unit ()) {
						return -1;
					}
					continue;
				} else if (!strcmp (arg, "fuzz")) {
					if (!opt->fuzz_dir) {
						R_LOG_ERROR ("No fuzz dir given. Use -F [dir]");
						return -1;
					}
					if (!r2r_test_database_load_fuzz (state->db, opt->fuzz_dir)) {
						R_LOG_ERROR ("Failed to load fuzz tests from \"%s\"", opt->fuzz_dir);
					}
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
			if (r_str_endswith (arg, ".c")) {
				char *abspath = strdup (arg);
				if (*arg != '/') {
					free (abspath);
					abspath = r_str_newf ("%s/%s", cwd, arg);
				}
				RList *tests = r_list_newf (free);
				r2r_from_sourcecomments (tests, abspath);
				free (abspath);
				RListIter *iter;
				char *test;
				int grc = 0;
				r_list_foreach (tests, iter, test) {
					R_LOG_INFO ("Running %s", test);
					int rc = r_sys_cmdf ("r2r %s %s", opt->interactive? "-i": "", test);
					if (rc != 0) {
						grc = rc;
					}
				}
				r_list_free (tests);
				return grc? grc: 1; // Signal special exit
			}
			char *tf = r_file_abspath_rel (cwd, arg);
			if (!tf || !r2r_test_database_load (state->db, tf, skip_json_tests)) {
				R_LOG_ERROR ("Failed to load tests from \"%s\"", tf);
				free (tf);
				return -1;
			}
			free (tf);
		}
	} else {
		if (!r2r_test_database_load (state->db, "db", skip_json_tests)) {
			R_LOG_ERROR ("Failed to load tests from ./db");
			return -1;
		}
		if (opt->fuzz_dir && !r2r_test_database_load_fuzz (state->db, opt->fuzz_dir)) {
			R_LOG_ERROR ("Failed to load fuzz tests from \"%s\"", opt->fuzz_dir);
		}
	}
	return 0;
}

static void r2r_setup_log_mode(R2RState *state) {
	state->path_left = ht_pp_new (NULL, path_left_free_kv, NULL);
	if (state->path_left) {
		R2RTest **it;
		R_VEC_FOREACH (&state->queue, it) {
			R2RTest *test = *it;
			ut64 *count = ht_pp_find (state->path_left, test->path, NULL);
			if (!count) {
				count = malloc (sizeof (ut64));
				*count = 0;
				ht_pp_insert (state->path_left, test->path, count);
			}
			(*count)++;
		}
	}
}

static bool r2r_run_workers(R2RState *state, R2ROptions *opt) {
	r_th_lock_enter (state->lock);

	RVecRThreadPtr workers;
	RVecRThreadPtr_init (&workers);

	int i;
	for (i = 0; i < opt->workers_count; i++) {
		RThread *th = r_th_new (worker_th, state, 0);
		if (!th) {
			R_LOG_ERROR ("Failed to setup thread");
			r_th_lock_leave (state->lock);
			RVecRThreadPtr_fini (&workers);
			return false;
		}
		if (!r_th_start (th)) {
			R_LOG_ERROR ("Failed to start thread");
			r_th_lock_leave (state->lock);
			r_th_free (th);
			RVecRThreadPtr_fini (&workers);
			return false;
		}
		RVecRThreadPtr_push_back (&workers, &th);
	}

	ut64 prev_completed = UT64_MAX;
	ut64 prev_paths_completed = 0;
	while (true) {
		ut64 completed = RVecR2RTestResultInfoPtr_length (&state->results);
		if (opt->log_mode) {
			print_log (state, prev_completed, prev_paths_completed);
		} else if (completed != prev_completed) {
			print_state (state, prev_completed);
		}
		prev_completed = completed;
		prev_paths_completed = RVecConstCharPtr_length (&state->completed_paths);
		if (completed == RVecR2RTestPtr_length (&state->db->tests)) {
			break;
		}
		r_th_cond_wait (state->cond, state->lock);
	}

	r_th_lock_leave (state->lock);

	RThread **it;
	R_VEC_FOREACH (&workers, it) {
		RThread *th = *it;
		r_th_wait (th);
		r_th_free (th);
	}
	RVecRThreadPtr_fini (&workers);

	return true;
}

static void r2r_print_summary(R2RState *state, ut64 time_start) {
	if (!state->quiet) {
		printf ("\n");
		ut64 seconds = (r_time_now_mono () - time_start) / 1000000;
		printf ("Finished in");
		if (seconds > 60) {
			ut64 minutes = seconds / 60;
			printf (" %" PFMT64d " minutes and", minutes);
			seconds -= (minutes * 60);
		}
		printf (" %" PFMT64d " seconds.\n", seconds % 60);
	}
}

static void r2r_write_output(R2RState *state, const char *output_file) {
	if (!output_file) {
		return;
	}
	pj_end (state->test_results);
	if (r_file_exists (output_file)) {
		R_LOG_WARN ("Overwrite output file '%s'", output_file);
	}
	char *results = pj_drain (state->test_results);
	char *output = r_str_newf ("%s\n", results);
	free (results);
	if (!r_file_dump (output_file, (ut8 *)output, strlen (output), false)) {
		R_LOG_ERROR ("Cannot write to %s", output_file);
	}
	free (output);
}

static void r2r_git(void) {
	int max = 10;
	while (max-- > 0) {
		if (r_file_is_directory (".git")) {
			break;
		}
		if (chdir ("..") == -1) {
			break;
		}
	}
	char *changes = r_sys_cmd_strf ("git diff --name-only");
	RList *lines = r_str_split_list (changes, "\n", 0);
	RList *tests = r_list_newf (free);
	RListIter *iter;
	char *line, *test;
	r_list_foreach (lines, iter, line) {
		if (r_str_endswith (line, ".c")) {
			r2r_from_sourcecomments (tests, line);
		}
	}
	r_list_foreach (tests, iter, test) {
		R_LOG_INFO ("Running r2r -i test/%s", test);
		r_sys_cmdf ("r2r -i test/%s", test);
	}
	r_list_free (lines);
	free (changes);
}

int main(int argc, char **argv) {
	int ret = 0;
#if R2__WINDOWS__
	UINT old_cp = GetConsoleOutputCP ();
	{
		HANDLE streams[] = { GetStdHandle (STD_OUTPUT_HANDLE), GetStdHandle (STD_ERROR_HANDLE) };
		DWORD mode;
		DWORD mode_flags = ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		int i;
		for (i = 0; i < R_ARRAY_SIZE (streams); i++) {
			GetConsoleMode (streams[i], &mode);
			SetConsoleMode (streams[i], mode | mode_flags);
		}
	}
#endif

	R2ROptions opt = r2r_options_init ();
	R2RState state;
	bool state_initialized = false;

	int arg_ind = r2r_parse_args (&opt, argc, argv);
	if (arg_ind < 0) {
		ret = arg_ind + 1; // when -1 return 0, when -2, return 1
		goto cleanup;
	}

	char *cwd = NULL;
	if (!r2r_setup_directory (&opt, arg_ind, argc, argv, &cwd)) {
		free (cwd);
		ret = -1;
		goto cleanup;
	}

	if (opt.fuzz_dir) {
		char *tmp = r_file_abspath_rel (cwd, opt.fuzz_dir);
		if (tmp) {
			free (opt.fuzz_dir);
			opt.fuzz_dir = tmp;
		}
	}

	if (opt.get_bins) {
		const char *cmd = r_file_is_directory ("bins")
			? "cd bins && git pull"
			: "git clone --depth 1 https://github.com/radareorg/radare2-testbins bins";
		r_sys_cmd (cmd);
	}

	if (!r2r_subprocess_init ()) {
		R_LOG_ERROR ("Subprocess init failed");
		free (cwd);
		ret = -1;
		goto cleanup;
	}
	atexit (r2r_subprocess_fini);

	r2r_print_lock = r_th_lock_new (false);
	r2r_setup_environment ();

	if (!r2r_state_init (&state, &opt)) {
		free (cwd);
		ret = -1;
		goto cleanup;
	}
	state_initialized = true;

	bool skip_json_tests = !r2r_check_jq_available ();
	int load_result = r2r_load_tests (&state, &opt, arg_ind, argc, argv, cwd, skip_json_tests);
	free (cwd);
	cwd = NULL;

	if (load_result < 0) {
		ret = -1;
		goto cleanup;
	}
	if (load_result > 0) {
		// Special exit (e.g., .c file handling returned a specific code)
		ret = (load_result == 1)? 0: load_result;
		goto cleanup;
	}

	ut64 loaded_tests = RVecR2RTestPtr_length (&state.db->tests);
	if (!state.quiet) {
		printf ("Loaded %" PFMT64u " tests.\n", loaded_tests);
	}

	if (skip_json_tests) {
		R_LOG_INFO ("Skipping json tests because jq is not available");
	}

	if (opt.nothing) {
		ret = 0;
		goto cleanup;
	}

	RVecR2RTestPtr_append (&state.queue, &state.db->tests, NULL);

	if (opt.log_mode) {
		r2r_setup_log_mode (&state);
	}

	ut64 time_start = r_time_now_mono ();

	if (!r2r_run_workers (&state, &opt)) {
		ret = -1;
		goto cleanup;
	}

	r2r_print_summary (&state, time_start);
	r2r_write_output (&state, opt.output_file);

	if (opt.interactive) {
		interact (&state);
	}

	if (state.counters[R2R_TEST_RESULT_FAILED]) {
		ret = 1;
	}

cleanup:
	if (state_initialized) {
		r2r_state_fini (&state);
	}
	r2r_options_fini (&opt);

restore_console:
#if R2__WINDOWS__
	if (old_cp) {
		(void)SetConsoleOutputCP (old_cp);
		(void)r_sys_cmdf ("chcp %u > NUL", old_cp);
	}
#endif
	return ret;
}

static void test_result_to_json(PJ *pj, R2RTestResultInfo *result) {
	R_RETURN_IF_FAIL (pj && result);
	pj_o (pj);
	pj_k (pj, "type");
	R2RTest *test = result->test;
	if (!test) {
		R_LOG_ERROR ("result->test shouldn't be null");
		pj_s (pj, "error");
		pj_end (pj);
		return;
	}
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		pj_s (pj, "cmd");
		if (test->cmd_test->name.value) {
			pj_ks (pj, "name", test->cmd_test->name.value);
		}
		break;
	case R2R_TEST_TYPE_ASM:
		pj_s (pj, "asm");
		pj_ks (pj, "arch", test->asm_test->arch);
		pj_ki (pj, "bits", test->asm_test->bits);
		pj_kn (pj, "line", test->asm_test->line);
		break;
	case R2R_TEST_TYPE_JSON:
		pj_s (pj, "json");
		pj_ks (pj, "cmd", test->json_test->cmd);
		break;
	case R2R_TEST_TYPE_FUZZ:
		pj_s (pj, "fuzz");
		pj_ks (pj, "file", test->fuzz_test->file);
		break;
	}
	pj_k (pj, "result");
	switch (result->result) {
	case R2R_TEST_RESULT_OK:
		pj_s (pj, "ok");
		break;
	case R2R_TEST_RESULT_FAILED:
		pj_s (pj, "failed");
		break;
	case R2R_TEST_RESULT_BROKEN:
		pj_s (pj, "broken");
		break;
	case R2R_TEST_RESULT_FIXED:
		pj_s (pj, "fixed");
		break;
	}
	pj_kb (pj, "run_failed", result->run_failed);
	pj_kn (pj, "time_elapsed", result->time_elapsed);
	pj_kb (pj, "timeout", result->timeout);
	pj_end (pj);
}

static RThreadFunctionRet worker_th(RThread *th) {
	R2RState *state = th->user;
	r_th_lock_enter (state->lock);
	while (true) {
		if (RVecR2RTestPtr_empty (&state->queue)) {
			break;
		}
		R2RTest **test_it = RVecR2RTestPtr_last (&state->queue);
		R2RTest *test = test_it? *test_it: NULL;
		RVecR2RTestPtr_pop_back (&state->queue);
		r_th_lock_leave (state->lock);
		R2RRunConfig *cfg = &state->run_config;

		R2RTestResultInfo *result = NULL;
		bool mustrun = true;
		if (cfg->shallow > 0) {
			// randomly skip
			int rn = r_num_rand (100);
			if (rn < cfg->shallow) {
				mustrun = false;
				state->sk_count++;
			}
		}
		if (mustrun) {
			result = r2r_run_test (cfg, test);
		} else {
			result = R_NEW0 (R2RTestResultInfo);
			result->result = R2R_TEST_RESULT_OK;
			result->run_skipped = true;
		}
		r_th_lock_enter (state->lock);
		RVecR2RTestResultInfoPtr_push_back (&state->results, &result);

		if (!result->run_skipped) {
			state->counters[result->result]++;
		}
		if (test && state->path_left) {
			ut64 *count = ht_pp_find (state->path_left, test->path, NULL);
			if (count) {
				(*count)--;
				if (!*count) {
					const char *path = test->path;
					RVecConstCharPtr_push_back (&state->completed_paths, &path);
				}
			}
		}
		r_th_cond_signal (state->cond);
	}
	r_th_lock_leave (state->lock);
	return R_TH_STOP;
}

static void print_diff(const char *actual, const char *expected, bool diffchar, const char *regexp) {
	RDiff *d = r_diff_new ();
#ifdef R2__WINDOWS__
	d->diff_cmd = "git diff --no-index";
#endif
	if (!actual) {
		actual = "";
	}
	if (!expected) {
		expected = "";
	}
	char *output = NULL;
	if (regexp) {
		RRegex *rx = r_regex_new (regexp, "en");
		RList *matches = r_regex_match_list (rx, actual);
		output = r_list_to_str (matches, '\0');
		r_list_free (matches);
		r_regex_free (rx);
		if (!output) {
			output = strdup ("");
		}
	} else {
		output = strdup (actual);
	}
	if (diffchar) {
		RDiffChar *diff = r_diffchar_new ((const ut8 *)expected, (const ut8 *)actual);
		if (diff) {
			r_diffchar_print (diff);
			r_diffchar_free (diff);
			goto cleanup;
		}
		d->diff_cmd = "git diff --no-index --word-diff=porcelain --word-diff-regex=.";
	}
	char *uni = r_diff_buffers_tostring (d, (const ut8 *)expected, (int)strlen (expected),
		(const ut8 *)output, (int)strlen (output));
	r_diff_free (d);

	RList *lines = r_str_split_duplist (uni, "\n", false);
	RListIter *it;
	char *line;
	bool header_found = false;
	r_list_foreach (lines, it, line) {
		if (!header_found) {
			if (r_str_startswith (line, "+++ ")) {
				header_found = true;
			}
			continue;
		}
		if (r_str_startswith (line, "@@ ") && r_str_endswith (line, " @@")) {
			printf ("%s%s%s\n", Color_CYAN, line, Color_RESET);
			continue;
		}
		bool color = true;
		char c = *line;
		switch (c) {
		case '+':
			printf ("%s" Color_INSERT, diffchar? Color_BGINSERT: "");
			break;
		case '-':
			printf ("%s" Color_DELETE, diffchar? Color_BGDELETE: "");
			break;
		case '~': // can't happen if !diffchar
			printf ("\n");
			continue;
		default:
			color = false;
			break;
		}
		if (diffchar) {
			printf ("%s", *line? line + 1: "");
		} else {
			printf ("%s\n", line);
		}
		if (color) {
			printf ("%s", Color_RESET);
		}
	}
	r_list_free (lines);
	free (uni);
	printf ("\n");
cleanup:
	free (output);
}

static R2RProcessOutput *print_runner(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	size_t i;
	for (i = 0; i < env_size; i++) {
		printf ("%s=%s ", envvars[i], envvals[i]);
	}
	printf ("%s", file);
	for (i = 0; i < args_size; i++) {
		const char *str = args[i];
		if (R_STR_ISEMPTY (str)) {
			break;
		}
		if (strpbrk (str, "\n \'\"")) {
			printf (" '%s'", str); // TODO: escape
		} else {
			printf (" %s", str);
		}
	}
	printf ("\n");
	return NULL;
}

R_API bool r_test_cmp_cmd_output(const char *output, const char *expect, const char *regexp) {
	if (regexp) {
		if (!r_regex_match (regexp, "e", output)) {
			return true;
		}
		return false;
	}
	return !strcmp (expect, output);
}

static void print_result_diff(R2RRunConfig *config, R2RTestResultInfo *result) {
	if (r2r_print_lock) {
		r_th_lock_enter (r2r_print_lock);
	}
	if (result->run_failed) {
		printf (Color_RED "RUN FAILED (e.g. wrong radare2 path)" Color_RESET "\n");
		if (r2r_print_lock) {
			r_th_lock_leave (r2r_print_lock);
		}
		return;
	}
	switch (result->test->type) {
	case R2R_TEST_TYPE_CMD:
		{
			r2r_run_cmd_test (config, result->test->cmd_test, print_runner, NULL);
			const char *expect = result->test->cmd_test->expect.value;
			const char *out = result->proc_out? result->proc_out->out: "";
			const char *regexp_out = result->test->cmd_test->regexp_out.value;
		if ((expect || regexp_out) && !r_test_cmp_cmd_output (out, expect, regexp_out)) {
				printf ("-- stdout\n");
				print_diff (out, expect, false, regexp_out);
			}
			expect = result->test->cmd_test->expect_err.value;
			const char *err = result->proc_out? result->proc_out->err: "";
			const char *regexp_err = result->test->cmd_test->regexp_err.value;
		if ((expect || regexp_err) && !r_test_cmp_cmd_output (err, expect, regexp_err)) {
				printf ("-- stderr\n");
				print_diff (err, expect, false, regexp_err);
			} else if (*err) {
				printf ("-- stderr\n%s\n", err);
			}
		if (result->proc_out && result->proc_out->ret != 0) {
				printf ("-- exit status: " Color_RED "%d" Color_RESET "\n", result->proc_out->ret);
			}
			break;
		}
	case R2R_TEST_TYPE_ASM:
		// TODO
		break;
	case R2R_TEST_TYPE_JSON:
		break;
	case R2R_TEST_TYPE_FUZZ:
		r2r_run_fuzz_test (config, result->test->path, print_runner, NULL);
		printf ("-- stdout\n%s\n", result->proc_out->out);
		printf ("-- stderr\n%s\n", result->proc_out->err);
		printf ("-- exit status: " Color_RED "%d" Color_RESET "\n", result->proc_out->ret);
		break;
	}
	if (r2r_print_lock) {
		r_th_lock_leave (r2r_print_lock);
	}
}

static void print_new_results(R2RState *state, ut64 prev_completed) {
	// Detailed test result (with diff if necessary)
	ut64 completed = RVecR2RTestResultInfoPtr_length (&state->results);
	ut64 i;
	for (i = prev_completed; i < completed; i++) {
		R2RTestResultInfo *result = *RVecR2RTestResultInfoPtr_at (&state->results, i);
		if (state->test_results && !result->run_skipped) {
			test_result_to_json (state->test_results, result);
		}
		/* In quiet mode only print failing tests; otherwise follow verbose flag rules */
		if (state->quiet) {
			if (result->result != R2R_TEST_RESULT_FAILED) {
				continue;
			}
		} else if (!state->verbose && (result->result == R2R_TEST_RESULT_OK || result->result == R2R_TEST_RESULT_FIXED || result->result == R2R_TEST_RESULT_BROKEN)) {
			continue;
		}
		char *name = r2r_test_name (result->test);
		if (!name) {
			continue;
		}
		printf ("\n" R_CONS_CURSOR_UP R_CONS_CLEAR_LINE);
		switch (result->result) {
		case R2R_TEST_RESULT_OK:
			printf (Color_GREEN "[OK]" Color_RESET);
			break;
		case R2R_TEST_RESULT_FAILED:
			printf (Color_RED "[XX]" Color_RESET);
			break;
		case R2R_TEST_RESULT_BROKEN:
			printf (Color_BLUE "[BR]" Color_RESET);
			break;
		case R2R_TEST_RESULT_FIXED:
			printf (Color_CYAN "[FX]" Color_RESET);
			break;
		}
		if (result->timeout) {
			printf (Color_CYAN " TIMEOUT" Color_RESET);
		}
		printf (" %s " Color_YELLOW "%s" Color_RESET "\n", result->test->path, name);
		if (result->result == R2R_TEST_RESULT_FAILED || (state->verbose && result->result == R2R_TEST_RESULT_BROKEN)) {
			print_result_diff (&state->run_config, result);
		}
		free (name);
	}
}

static void print_state_counts(R2RState *state) {
	printf ("%8" PFMT64u " OK  %8" PFMT64u " BR %8" PFMT64u " XX %8" PFMT64u " SK %8" PFMT64u " FX",
		state->counters[R2R_TEST_RESULT_OK], state->counters[R2R_TEST_RESULT_BROKEN],
		state->counters[R2R_TEST_RESULT_FAILED], state->sk_count,
		state->counters[R2R_TEST_RESULT_FIXED]);
}

static void print_state(R2RState *state, ut64 prev_completed) {
#if R2__WINDOWS__
	setvbuf (stdout, NULL, _IOFBF, 8192);
#endif
	/* Always print new failing results; in quiet mode skip summary/status line */
	print_new_results (state, prev_completed);
	if (state->quiet) {
		return;
	}

	/* [x/x] OK  42 BR  0 ... */
	printf (R_CONS_CLEAR_LINE);
	ut64 a = RVecR2RTestResultInfoPtr_length (&state->results);
	ut64 b = RVecR2RTestPtr_length (&state->db->tests);
	int w = printf ("[%" PFMT64u "/%" PFMT64u "]", a, b);
	while (w >= 0 && w < 20) {
		printf (" ");
		w++;
	}
	printf (" ");
	print_state_counts (state);
	fflush (stdout);
#if R2__WINDOWS__
	setvbuf (stdout, NULL, _IONBF, 0);
#endif
}

static void print_log(R2RState *state, ut64 prev_completed, ut64 prev_paths_completed) {
	/* Always print new failing results; in quiet mode skip per-path summaries */
	print_new_results (state, prev_completed);
	if (state->quiet) {
		return;
	}
	ut64 paths_completed = RVecConstCharPtr_length (&state->completed_paths);
	int a = (int)RVecR2RTestPtr_length (&state->queue);
	for (; prev_paths_completed < paths_completed; prev_paths_completed++) {
		printf ("[%d/%d] %40s ",
			(int)paths_completed,
			(int) (a + prev_paths_completed),
			*RVecConstCharPtr_at (&state->completed_paths, prev_paths_completed));
		print_state_counts (state);
		printf ("\n");
	}
}

static void interact(R2RState *state) {
	R2RTestResultInfo **it;
	RVecR2RTestResultInfoPtr failed_results;
	RVecR2RTestResultInfoPtr_init (&failed_results);
	R_VEC_FOREACH (&state->results, it) {
		R2RTestResultInfo *result = *it;
		if (result->result == R2R_TEST_RESULT_FAILED) {
			RVecR2RTestResultInfoPtr_push_back (&failed_results, &result);
		}
	}
	if (RVecR2RTestResultInfoPtr_empty (&failed_results)) {
		goto beach;
	}

	bool use_fancy_stuff = !r_cons_is_windows ();
#if R2__WINDOWS__
	// XXX move to rcons
	(void)SetConsoleOutputCP (65001); // UTF-8
#endif
	printf ("\n");
	printf ("#####################\n");
	if (use_fancy_stuff) {
		printf (" %" PFMT64u " failed test(s)" R_UTF8_POLICE_CARS_REVOLVING_LIGHT "\n",
			RVecR2RTestResultInfoPtr_length (&failed_results));
	} else {
		printf (" %" PFMT64u " failed test(s)\n", RVecR2RTestResultInfoPtr_length (&failed_results));
	}
	bool always_fix = false;

	R_VEC_FOREACH (&failed_results, it) {
		R2RTestResultInfo *result = *it;
		if (result->test->type != R2R_TEST_TYPE_CMD) {
			// TODO: other types of tests
			continue;
		}

		printf ("#####################\n\n");
		print_result_diff (&state->run_config, result);
	menu:
		if (use_fancy_stuff) {
			printf ("Wat do?    "
			"(f)ix " R_UTF8_WHITE_HEAVY_CHECK_MARK R_UTF8_VS16 R_UTF8_VS16 R_UTF8_VS16 "  "
			"(F)ixAll " R_UTF8_WHITE_HEAVY_CHECK_MARK R_UTF8_VS16 R_UTF8_VS16 R_UTF8_VS16 "  "
			"(i)gnore " R_UTF8_SEE_NO_EVIL_MONKEY "  "
			"(b)roken " R_UTF8_SKULL_AND_CROSSBONES R_UTF8_VS16 R_UTF8_VS16 R_UTF8_VS16 "  "
			"(c)ommands " R_UTF8_KEYBOARD R_UTF8_VS16 "  "
			"(d)iffchar " R_UTF8_LEFT_POINTING_MAGNIFYING_GLASS "  "
			"(q)uit " R_UTF8_DOOR "\n");
		} else {
			printf ("Wat do?  (f)ix  (F)ixAll  (i)gnore  (b)roken  (c)ommands  (d)iffchar  (q)uit\n");
		}
		char buf[32] = { 0 };
		if (always_fix) {
			printf ("> f\n");
			fflush (stdout);
			r_str_ncpy (buf, "f", sizeof (buf));
		} else {
			printf ("> ");
			fflush (stdout);
			if (!fgets (buf, sizeof (buf) - 1, stdin)) {
				break;
			}
			r_str_trim (buf);
			if (buf[1]) {
				// LOL
				goto menu;
			}
		}
		if (buf[0] == 'F') {
			always_fix = true;
			buf[0] = 'f';
		}
		switch (buf[0]) {
		case 'f':
			if (result->run_failed || result->proc_out->ret != 0) {
				printf ("This test has failed too hard to be fixed.\n");
				goto menu;
			}
			interact_fix (result, &failed_results);
			break;
		case 'i':
			// do nothing on purpose
			break;
		case 'b':
			interact_break (result, &failed_results);
			break;
		case 'c':
			interact_commands (result, &failed_results);
			break;
		case 'd':
			interact_diffchar (result);
			goto menu;
		case 'q':
			goto beach;
		default:
			goto menu;
		}
	}

beach:
	RVecR2RTestResultInfoPtr_fini (&failed_results);
}

static char *format_cmd_kv(const char *key, const char *val) {
	RStrBuf buf;
	r_strbuf_init (&buf);
	r_strbuf_appendf (&buf, "%s=", key);
	if (strchr (val, '\n')) {
		r_strbuf_appendf (&buf, "<<EOF\n%sEOF", val);
	} else {
		r_strbuf_append (&buf, val);
	}
	return r_strbuf_drain_nofree (&buf);
}

static char *replace_lines(const char *src, size_t from, size_t to, const char *news) {
	const char *begin = src;
	size_t line = 1;
	while (line < from) {
		begin = strchr (begin, '\n');
		if (!begin) {
			break;
		}
		begin++;
		line++;
	}
	if (!begin) {
		return NULL;
	}

	const char *end = begin;
	while (line < to) {
		end = strchr (end, '\n');
		if (!end) {
			break;
		}
		end++;
		line++;
	}

	RStrBuf buf;
	r_strbuf_init (&buf);
	r_strbuf_append_n (&buf, src, begin - src);
	r_strbuf_append (&buf, news);
	r_strbuf_append (&buf, "\n");
	if (end) {
		r_strbuf_append (&buf, end);
	}
	return r_strbuf_drain_nofree (&buf);
}

// After editing a test, fix the line numbers previously saved for all the other tests
static void fixup_tests(RVecR2RTestResultInfoPtr *results, const char *edited_file, ut64 start_line, st64 delta) {
	R2RTestResultInfo **it;
	R_VEC_FOREACH (results, it) {
		R2RTestResultInfo *result = *it;
		if (result->test->type != R2R_TEST_TYPE_CMD) {
			continue;
		}
		if (result->test->path != edited_file) { // this works because all the paths come from the string pool
			continue;
		}
		R2RCmdTest *test = result->test->cmd_test;
		test->run_line += delta;

#define DO_KEY_STR(key, field) \
	if (test->field.value) { \
		if (test->field.line_begin >= start_line) { \
			test->field.line_begin += delta; \
		} \
		if (test->field.line_end >= start_line) { \
			test->field.line_end += delta; \
		} \
	}

#define DO_KEY_BOOL(key, field) \
	if (test->field.set && test->field.line >= start_line) { \
		test->field.line += delta; \
	}

#define DO_KEY_NUM(key, field) \
	if (test->field.set && test->field.line >= start_line) { \
		test->field.line += delta; \
	}

		R2R_CMD_TEST_FOREACH_RECORD (DO_KEY_STR, DO_KEY_BOOL, DO_KEY_NUM)
#undef DO_KEY_STR
#undef DO_KEY_BOOL
#undef DO_KEY_NUM
	}
}

static char *replace_cmd_kv(const char *path, const char *content, size_t line_begin, size_t line_end, const char *key, const char *value, RVecR2RTestResultInfoPtr *fixup_results) {
	char *kv = format_cmd_kv (key, value);
	if (!kv) {
		return NULL;
	}
	size_t kv_lines = r_str_char_count (kv, '\n') + 1;
	char *newc = replace_lines (content, line_begin, line_end, kv);
	free (kv);
	if (!newc) {
		return NULL;
	}
	size_t lines_before = line_end - line_begin;
	st64 delta = (st64)kv_lines - (st64)lines_before;
	if (line_end == line_begin) {
		delta++;
	}
	fixup_tests (fixup_results, path, line_end, delta);
	return newc;
}

static void replace_cmd_kv_file(const char *path, ut64 line_begin, ut64 line_end, const char *key, const char *value, RVecR2RTestResultInfoPtr *fixup_results) {
	char *content = r_file_slurp (path, NULL);
	if (!content) {
		R_LOG_ERROR ("Failed to read file \"%s\"", path);
		return;
	}
	char *newc = replace_cmd_kv (path, content, line_begin, line_end, key, value, fixup_results);
	free (content);
	if (!newc) {
		return;
	}
	if (r_file_dump (path, (const ut8 *)newc, -1, false)) {
#if R2__UNIX__ && !(__wasi__ || __EMSCRIPTEN__)
		sync ();
#endif
	} else {
		R_LOG_ERROR ("Failed to write file \"%s\"", path);
	}
	free (newc);
}

static void interact_fix(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results) {
	R_RETURN_IF_FAIL (result->test->type == R2R_TEST_TYPE_CMD);
	R2RCmdTest *test = result->test->cmd_test;
	R2RProcessOutput *out = result->proc_out;
	if (test->expect.value && out->out) {
		replace_cmd_kv_file (result->test->path,
			test->expect.line_begin, test->expect.line_end,
			"EXPECT", out->out, fixup_results);
	}
	if (test->expect_err.value && out->err) {
		replace_cmd_kv_file (result->test->path,
			test->expect_err.line_begin, test->expect_err.line_end,
			"EXPECT_ERR", out->err, fixup_results);
	}
}

static void interact_break(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results) {
	R_RETURN_IF_FAIL (result->test->type == R2R_TEST_TYPE_CMD);
	R2RCmdTest *test = result->test->cmd_test;
	ut64 line_begin, line_end;
	if (test->broken.set) {
		line_begin = test->broken.set;
		line_end = line_begin + 1;
	} else {
		line_begin = line_end = test->run_line;
	}
	replace_cmd_kv_file (result->test->path, line_begin, line_end, "BROKEN", "1", fixup_results);
}

static void interact_commands(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results) {
	R_RETURN_IF_FAIL (result->test->type == R2R_TEST_TYPE_CMD);
	R2RCmdTest *test = result->test->cmd_test;
	if (!test->cmds.value) {
		return;
	}
	char *name = NULL;
	int fd = r_file_mkstemp ("r2r-cmds", &name);
	if (fd == -1) {
		free (name);
		R_LOG_ERROR ("Failed to open tmp file");
		return;
	}
	size_t cmds_sz = strlen (test->cmds.value);
	if (write (fd, test->cmds.value, cmds_sz) != cmds_sz) {
		R_LOG_ERROR ("Failed to write to tmp file");
		free (name);
		close (fd);
		return;
	}
	close (fd);

	char *editor = r_sys_getenv ("EDITOR");
	if (!editor || !*editor) {
		free (editor);
		editor = strdup ("vim");
		if (!editor) {
			free (name);
			return;
		}
	}
	r_sys_cmdf ("%s '%s'", editor, name);
	free (editor);

	char *newcmds = r_file_slurp (name, NULL);
	if (!newcmds) {
		R_LOG_ERROR ("Failed to read edited command file");
		free (name);
		return;
	}
	r_str_trim (newcmds);

	// if it's multiline we want exactly one trailing newline
	if (strchr (newcmds, '\n')) {
		char *tmp = newcmds;
		newcmds = r_str_newf ("%s\n", newcmds);
		free (tmp);
		if (!newcmds) {
			free (name);
			return;
		}
	}

	replace_cmd_kv_file (result->test->path, test->cmds.line_begin, test->cmds.line_end, "CMDS", newcmds, fixup_results);
	free (name);
	free (newcmds);
}

static void interact_diffchar(R2RTestResultInfo *result) {
	const char *actual = result->proc_out->out;
	const char *expected = result->test->cmd_test->expect.value;
	const char *regexp_out = result->test->cmd_test->regexp_out.value;
	printf ("-- stdout\n");
	print_diff (actual, expected, true, regexp_out);
}
