
#define R_LOG_ORIGIN "r2r"
#define main not_main
#include "../../binr/r2r/r2r.c"
#undef R_LOG_ORIGIN
#include "../../binr/r2r/load.c"
#include "../../binr/r2r/run.c"
#undef main

#include "minunit.h"

#define FILENAME "unit/r2r_cmd_test"

bool test_r2r_database_load_cmd(void) {
	R2RTestDatabase *db = r2r_test_database_new ();
	database_load (db, FILENAME, 1, false, false);

	mu_assert_eq (RVecR2RTestPtr_length (&db->tests), 4, "tests count");

	R2RTest *test = *RVecR2RTestPtr_at (&db->tests, 0);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	R2RCmdTest *cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "multiline0", "name");
	mu_assert_streq (cmd_test->file.value, "-", "file");
	mu_assert_streq (cmd_test->cmds.value, "rm -rf /\n", "cmds");
	mu_assert_streq (cmd_test->expect.value, "expected\noutput\n", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 6, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 10, "line begin");

	test = *RVecR2RTestPtr_at (&db->tests, 1);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "singleline0", "name");
	mu_assert_streq (cmd_test->expect.value, "", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 17, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 18, "line begin");

	test = *RVecR2RTestPtr_at (&db->tests, 2);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "multiline1", "name");
	mu_assert_streq (cmd_test->expect.value, "more\nexpected\noutput\n", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 25, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 30, "line begin");

	test = *RVecR2RTestPtr_at (&db->tests, 3);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "singleline1", "name");
	mu_assert_streq (cmd_test->expect.value, "", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 37, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 38, "line begin");

	r2r_test_database_free (db);
	mu_end;
}

bool test_r2r_fix(void) {
	R2RTestDatabase *db = r2r_test_database_new ();
	database_load (db, FILENAME, 1, false, false);

	RVecR2RTestResultInfoPtr results;
	RVecR2RTestResultInfoPtr_init (&results);

	R2RTestResultInfo *result0 = R_NEW0 (R2RTestResultInfo);
	RVecR2RTestResultInfoPtr_push_back (&results, &result0);
	if (RVecR2RTestPtr_length (&db->tests) == 0) {
		eprintf ("Empty tests database. Please run this binary from the test/ directory.\n");
		return false;
	}
	result0->test = *RVecR2RTestPtr_at (&db->tests, 0);
	result0->result = R2R_TEST_RESULT_FAILED;
	result0->proc_out = R_NEW0 (R2RProcessOutput);
	result0->proc_out->out = strdup ("fixed\nresult\nfor\n0\n");
	result0->proc_out->err = strdup ("");

	R2RTestResultInfo *result1 = R_NEW0 (R2RTestResultInfo);
	RVecR2RTestResultInfoPtr_push_back (&results, &result1);
	result1->test = *RVecR2RTestPtr_at (&db->tests, 1);
	result1->result = R2R_TEST_RESULT_FAILED;
	result1->proc_out = R_NEW0 (R2RProcessOutput);
	result1->proc_out->out = strdup ("fixed\nresult\nfor\n1\n");
	result1->proc_out->err = strdup ("");

	R2RTestResultInfo *result2 = R_NEW0 (R2RTestResultInfo);
	RVecR2RTestResultInfoPtr_push_back (&results, &result2);
	result2->test = *RVecR2RTestPtr_at (&db->tests, 2);
	result2->result = R2R_TEST_RESULT_FAILED;
	result2->proc_out = R_NEW0 (R2RProcessOutput);
	result2->proc_out->out = strdup ("fixed\nresult\nfor\n2\n");
	result2->proc_out->err = strdup ("");

	R2RTestResultInfo *result3 = R_NEW0 (R2RTestResultInfo);
	RVecR2RTestResultInfoPtr_push_back (&results, &result3);
	result3->test = *RVecR2RTestPtr_at (&db->tests, 3);
	result3->result = R2R_TEST_RESULT_FAILED;
	result3->proc_out = R_NEW0 (R2RProcessOutput);
	result3->proc_out->out = strdup ("fixed\nresult\nfor\n3\n");
	result3->proc_out->err = strdup ("");

	char *content = r_file_slurp (FILENAME, NULL);
	mu_assert ("test file", content);

	char *newc = replace_cmd_kv (result0->test->path, content, result0->test->cmd_test->expect.line_begin,
			result0->test->cmd_test->expect.line_end, "EXPECT", result0->proc_out->out, &results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result1->test->path, content, result1->test->cmd_test->expect.line_begin,
			result1->test->cmd_test->expect.line_end, "EXPECT", result1->proc_out->out, &results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result2->test->path, content, result2->test->cmd_test->expect.line_begin,
			result2->test->cmd_test->expect.line_end, "EXPECT", result2->proc_out->out, &results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result3->test->path, content, result3->test->cmd_test->expect.line_begin,
			result3->test->cmd_test->expect.line_end, "EXPECT", result3->proc_out->out, &results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	R2RTestResultInfo **it;
	R_VEC_FOREACH (&results, it) {
		r2r_test_result_info_free (*it);
	}
	RVecR2RTestResultInfoPtr_fini (&results);

	mu_assert_streq (content,
		"NAME=multiline0\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf /\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"0\n"
		"EOF\n"
		"RUN\n"
		"\n"
		"NAME=singleline0\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"1\n"
		"EOF\n"
		"RUN\n"
		"\n"
		"NAME=multiline1\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"2\n"
		"EOF\n"
		"RUN\n"
		"\n"
		"NAME=singleline1\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"3\n"
		"EOF\n"
		"RUN", "fixed contents");

	free (content);

	r2r_test_database_free (db);
	mu_end;
}

bool test_r2r_require(void) {
	mu_assert_true (require_check (NULL, 0), "empty requirement");
	mu_assert_true (require_check ("", 0), "empty requirement");
	mu_assert_true (require_check ("cs5", 5), "Capstone 5 requirement");
	mu_assert_false (require_check ("cs5", 6), "Capstone 5 excludes Capstone 6");
	mu_assert_true (require_check ("cs6", 6), "Capstone 6 requirement");
	mu_assert_false (require_check ("cs6", 5), "Capstone 6 excludes Capstone 5");
	mu_assert_false (require_check ("cs5", 0), "missing Capstone 5");
	mu_assert_false (require_check ("cs6", 0), "missing Capstone 6");
	mu_assert_false (require_check ("cs5, cs6", 5), "requirements are conjunctive");
	mu_assert_false (require_check ("cs5;cs6", 6), "semicolon separator");
	mu_assert_true (require_check ("cs60", 5), "match whole tokens");
#if R_SYS_ENDIAN == 0
	mu_assert_true (require_check ("little cs6", 6), "combined requirement");
	mu_assert_true (require_check ("little", 0), "little endian requirement");
#else
	mu_assert_false (require_check ("little cs6", 6), "combined requirement");
	mu_assert_false (require_check ("little", 0), "little endian requirement");
#endif
	mu_end;
}

bool test_r2r_asm_require(void) {
	R2RTestDatabase *db = r2r_test_database_new ();
	RVecR2RAsmTestPtr *tests = r2r_load_asm_test_file (&db->strpool, "unit/r2r_asm_test");
	mu_assert_notnull (tests, "load assembly requirements");
	mu_assert_eq (RVecR2RAsmTestPtr_length (tests), 4, "assembly test count");
	mu_assert_null ((*RVecR2RAsmTestPtr_at (tests, 0))->require, "no initial requirement");
	mu_assert_streq ((*RVecR2RAsmTestPtr_at (tests, 1))->require, "cs5", "Capstone 5 block");
	mu_assert_streq ((*RVecR2RAsmTestPtr_at (tests, 2))->require, "cs6", "Capstone 6 block");
	mu_assert_streq ((*RVecR2RAsmTestPtr_at (tests, 3))->require, "", "reset requirement");
	mu_assert_eq ((*RVecR2RAsmTestPtr_at (tests, 3))->line, 7, "preserve source line numbers");
	R2RRunConfig config = { .capstone_version = 5 };
	R2RTest test = { .type = R2R_TEST_TYPE_ASM, .asm_test = *RVecR2RAsmTestPtr_at (tests, 2) };
	R2RTestResultInfo *result = r2r_run_test (&config, &test);
	mu_assert_true (result->run_skipped, "skip mismatched assembly test before spawning");
	r2r_test_result_info_free (result);
	R2RCmdTest cmd_test = { .require.value = "cs6" };
	test.type = R2R_TEST_TYPE_CMD;
	test.cmd_test = &cmd_test;
	result = r2r_run_test (&config, &test);
	mu_assert_true (result->run_skipped, "skip mismatched command test before spawning");
	r2r_test_result_info_free (result);
	R2RAsmTest **it;
	R_VEC_FOREACH (tests, it) {
		r2r_asm_test_free (*it);
	}
	RVecR2RAsmTestPtr_free (tests);
	r2r_test_database_free (db);
	mu_end;
}

bool test_r2r_worker_count_overflow(void) {
	char *previous = r_sys_getenv ("R2R_JOBS");
	r_sys_setenv ("R2R_JOBS", "4294967296");
	R2ROptions options = r2r_options_init ();
	r_sys_setenv ("R2R_JOBS", previous);
	free (previous);
	int workers = options.workers_count;
	r2r_options_fini (&options);
	mu_assert ("oversized job count must not wrap to zero and stall the runner", workers > 0);
	mu_end;
}

bool test_r2r_skipped_categories(void) {
	R2RRunConfig config = { .skip_cmd = true, .skip_asm = true, .skip_json = true, .skip_fuzz = true, .skip_leak = true };
	R2RCmdTest cmd = {0};
	R2RAsmTest asm_test = {0};
	R2RJsonTest json = {0};
	R2RTest tests[] = {
		{ .type = R2R_TEST_TYPE_CMD, .cmd_test = &cmd },
		{ .type = R2R_TEST_TYPE_ASM, .asm_test = &asm_test },
		{ .type = R2R_TEST_TYPE_JSON, .json_test = &json },
		{ .type = R2R_TEST_TYPE_FUZZ },
		{ .type = R2R_TEST_TYPE_LEAK, .cmd_test = &cmd },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tests); i++) {
		R2RTestResultInfo *result = r2r_run_test (&config, &tests[i]);
		bool skipped = result->run_skipped;
		r2r_test_result_info_free (result);
		mu_assert_true (skipped, "disabled category is skipped, not passed");
	}
	mu_end;
}

typedef struct {
	int calls;
	int ret;
	bool timeout;
	const char *output;
} RepeatRunner;

static R2RProcessOutput *fail_first_run(const char *file, const char *args[], size_t args_size, const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	RepeatRunner *state = user;
	bool first = !state->calls++;
	R2RProcessOutput *out = R_NEW0 (R2RProcessOutput);
	out->ret = first? state->ret: 0;
	out->timeout = first && state->timeout;
	out->out = strdup (first? state->output: "");
	out->err = strdup ("");
	return out;
}

bool test_r2r_repeat_failure(void) {
	R2RRunConfig config = { .r2_cmd = "mock", .timeout_ms = 1000 };
	R2RCmdTest test = { .cmds.value = "q", .repeat.value = 2, .expect.value = "" };
	RepeatRunner cases[] = {
		{ .ret = 1, .output = "" },
		{ .timeout = true, .output = "" },
		{ .output = "unexpected" },
		{ .output = "" },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		R2RProcessOutput *out = r2r_run_cmd_test (&config, &test, fail_first_run, &cases[i]);
		bool passed = r2r_check_cmd_test (out, &test);
		r2r_process_output_free (out);
		mu_assert_eq (passed, i == 3, "check every repetition, including exit, timeout and output");
		mu_assert_eq (cases[i].calls, i == 3? 2: 1, "stop repeating a failed test");
	}
	mu_end;
}

#if R2__UNIX__ && !__wasi__
bool test_r2r_closed_stdin(void) {
	mu_assert_true (r2r_subprocess_init (), "initialize subprocesses");
	const char *args[] = { "-c", "exit 0" };
	R2RSubprocess *proc = r2r_subprocess_start ("/bin/sh", args, R_ARRAY_SIZE (args), NULL, NULL, 0);
	bool complete = proc && r2r_subprocess_wait (proc, 5000);
	if (proc) {
		r2r_subprocess_stdin_write (proc, (const ut8 *)"input", 5);
		r2r_subprocess_free (proc);
	}
	r2r_subprocess_fini ();
	mu_assert_true (complete, "a child that closes stdin must not kill the runner with SIGPIPE");
	mu_end;
}

bool test_r2r_pending_sigpipe(void) {
	int fds[2];
	mu_assert_eq (pipe (fds), 0, "create a pipe");
	close (fds[0]);
	R2RSubprocess proc = { .stdin_fd = fds[1] };
	sigset_t blocked, previous, pending, restored;
	sigemptyset (&blocked);
	sigaddset (&blocked, SIGPIPE);
	r_signal_sigmask (SIG_BLOCK, &blocked, &previous);
	raise (SIGPIPE);
	r2r_subprocess_stdin_write (&proc, (const ut8 *)"input", 5);
	sigpending (&pending);
	r_signal_sigmask (SIG_BLOCK, NULL, &restored);
	bool kept_pending = sigismember (&pending, SIGPIPE) == 1;
	if (kept_pending) {
		int signal_number;
		sigwait (&blocked, &signal_number);
	}
	r_signal_sigmask (SIG_SETMASK, &previous, NULL);
	mu_assert_true (kept_pending, "preserve a SIGPIPE that was pending before the write");
	mu_assert_eq (sigismember (&restored, SIGPIPE), 1, "preserve the caller's signal mask");
	mu_assert_eq (proc.stdin_fd, -1, "close stdin after a failed write");
	mu_end;
}

bool test_r2r_descendant_timeout(void) {
	mu_assert_true (r2r_subprocess_init (), "initialize subprocesses");
	const char *args[] = { "-c", "exec 3<&0; read value <&3 &" };
	R2RSubprocess *proc = r2r_subprocess_start ("/bin/sh", args, R_ARRAY_SIZE (args), NULL, NULL, 0);
	bool started = proc != NULL;
	bool complete = proc && r2r_subprocess_wait (proc, 500);
	if (proc) {
		r2r_subprocess_kill (proc);
		r2r_subprocess_free (proc);
	}
	r2r_subprocess_fini ();
	mu_assert_true (started, "start child with a descendant holding its output pipes");
	mu_assert_false (complete, "exit of the direct child must not hide an output-drain timeout");
	mu_end;
}

bool test_r2r_runner_stdin_eof(void) {
	mu_assert_true (r2r_subprocess_init (), "initialize subprocesses");
	const char *args[] = { "-c", "cat" };
	R2RProcessOutput *out = subprocess_runner ("/bin/sh", args, R_ARRAY_SIZE (args), NULL, NULL, 0, 500, NULL);
	bool complete = out && !out->timeout && out->ret == 0;
	r2r_process_output_free (out);
	r2r_subprocess_fini ();
	mu_assert_true (complete, "commands without input must see stdin EOF");
	mu_end;
}

bool test_r2r_sibling_pipe_inheritance(void) {
	mu_assert_true (r2r_subprocess_init (), "initialize subprocesses");
	const char *reader_args[] = { "-c", "read value" };
	R2RSubprocess *reader = r2r_subprocess_start ("/bin/sh", reader_args, R_ARRAY_SIZE (reader_args), NULL, NULL, 0);
	bool isolated = false;
	if (reader) {
		r_strf_var (command, 80, "test ! -e /dev/fd/%d", reader->stdin_fd);
		const char *args[] = { "-c", command };
		R2RSubprocess *sibling = r2r_subprocess_start ("/bin/sh", args, R_ARRAY_SIZE (args), NULL, NULL, 0);
		if (sibling) {
			isolated = r2r_subprocess_wait (sibling, 5000) && sibling->ret == 0;
			r2r_subprocess_free (sibling);
		}
		r2r_subprocess_stdin_write (reader, (const ut8 *)"\n", 1);
		if (!r2r_subprocess_wait (reader, 5000)) {
			r2r_subprocess_kill (reader);
		}
		r2r_subprocess_free (reader);
	}
	r2r_subprocess_fini ();
	mu_assert_true (isolated, "a sibling must not inherit another child's stdin writer");
	mu_end;
}
#endif

int all_tests(void) {
	mu_run_test (test_r2r_database_load_cmd);
	mu_run_test (test_r2r_fix);
	mu_run_test (test_r2r_require);
	mu_run_test (test_r2r_asm_require);
	mu_run_test (test_r2r_worker_count_overflow);
	mu_run_test (test_r2r_skipped_categories);
	mu_run_test (test_r2r_repeat_failure);
#if R2__UNIX__ && !__wasi__
	mu_run_test (test_r2r_closed_stdin);
	mu_run_test (test_r2r_pending_sigpipe);
	mu_run_test (test_r2r_descendant_timeout);
	mu_run_test (test_r2r_sibling_pipe_inheritance);
	mu_run_test (test_r2r_runner_stdin_eof);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	setvbuf (stdout, NULL, _IONBF, 0);
	return all_tests();
}
