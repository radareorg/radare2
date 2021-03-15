
#define main not_main
#include "../../binr/r2r/r2r.c"
#include "../../binr/r2r/load.c"
#include "../../binr/r2r/run.c"
#undef main

#include "minunit.h"

#define FILENAME "unit/r2r_cmd_test"

bool test_r2r_database_load_cmd(void) {
	R2RTestDatabase *db = r2r_test_database_new ();
	database_load (db, FILENAME, 1);

	mu_assert_eq (r_pvector_len (&db->tests), 4, "tests count");

	R2RTest *test = r_pvector_at (&db->tests, 0);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	R2RCmdTest *cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "multiline0", "name");
	mu_assert_streq (cmd_test->file.value, "-", "file");
	mu_assert_streq (cmd_test->cmds.value, "rm -rf /\n", "cmds");
	mu_assert_streq (cmd_test->expect.value, "expected\noutput\n", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 6, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 10, "line begin");

	test = r_pvector_at (&db->tests, 1);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "singleline0", "name");
	mu_assert_streq (cmd_test->expect.value, "", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 17, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 18, "line begin");

	test = r_pvector_at (&db->tests, 2);
	mu_assert_eq (test->type, R2R_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "multiline1", "name");
	mu_assert_streq (cmd_test->expect.value, "more\nexpected\noutput\n", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 25, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 30, "line begin");

	test = r_pvector_at (&db->tests, 3);
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
	database_load (db, FILENAME, 1);

	RPVector *results = r_pvector_new ((RPVectorFree)r2r_test_result_info_free);

	R2RTestResultInfo *result0 = R_NEW0 (R2RTestResultInfo);
	r_pvector_push (results, result0);
	result0->test = r_pvector_at (&db->tests, 0);
	result0->result = R2R_TEST_RESULT_FAILED;
	result0->proc_out = R_NEW0 (R2RProcessOutput);
	result0->proc_out->out = strdup ("fixed\nresult\nfor\n0\n");
	result0->proc_out->err = strdup ("");

	R2RTestResultInfo *result1 = R_NEW0 (R2RTestResultInfo);
	r_pvector_push (results, result1);
	result1->test = r_pvector_at (&db->tests, 1);
	result1->result = R2R_TEST_RESULT_FAILED;
	result1->proc_out = R_NEW0 (R2RProcessOutput);
	result1->proc_out->out = strdup ("fixed\nresult\nfor\n1\n");
	result1->proc_out->err = strdup ("");

	R2RTestResultInfo *result2 = R_NEW0 (R2RTestResultInfo);
	r_pvector_push (results, result2);
	result2->test = r_pvector_at (&db->tests, 2);
	result2->result = R2R_TEST_RESULT_FAILED;
	result2->proc_out = R_NEW0 (R2RProcessOutput);
	result2->proc_out->out = strdup ("fixed\nresult\nfor\n2\n");
	result2->proc_out->err = strdup ("");

	R2RTestResultInfo *result3 = R_NEW0 (R2RTestResultInfo);
	r_pvector_push (results, result3);
	result3->test = r_pvector_at (&db->tests, 3);
	result3->result = R2R_TEST_RESULT_FAILED;
	result3->proc_out = R_NEW0 (R2RProcessOutput);
	result3->proc_out->out = strdup ("fixed\nresult\nfor\n3\n");
	result3->proc_out->err = strdup ("");

	char *content = r_file_slurp (FILENAME, NULL);
	mu_assert ("test file", content);

	char *newc = replace_cmd_kv (result0->test->path, content, result0->test->cmd_test->expect.line_begin,
			result0->test->cmd_test->expect.line_end, "EXPECT", result0->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result1->test->path, content, result1->test->cmd_test->expect.line_begin,
			result1->test->cmd_test->expect.line_end, "EXPECT", result1->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result2->test->path, content, result2->test->cmd_test->expect.line_begin,
			result2->test->cmd_test->expect.line_end, "EXPECT", result2->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result3->test->path, content, result3->test->cmd_test->expect.line_begin,
			result3->test->cmd_test->expect.line_end, "EXPECT", result3->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	r_pvector_free (results);

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

int all_tests() {
	mu_run_test (test_r2r_database_load_cmd);
	mu_run_test (test_r2r_fix);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
