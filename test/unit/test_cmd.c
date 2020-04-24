#include <r_cmd.h>
#include <stdlib.h>
#include "minunit.h"

bool test_parsed_args_noargs(void) {
	RCmdParsedArgs *a = r_cmd_parsed_args_new ("pd", 0, NULL);
	mu_assert_streq (a->argv[0], "pd", "pd is the command");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "", "empty arguments");
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), "pd", "only command");
	r_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_onearg(void) {
	char *args[] = {"10"};
	RCmdParsedArgs *a = r_cmd_parsed_args_new ("pd", 1, args);
	mu_assert_streq (a->argv[0], "pd", "pd is the command");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "10", "one argument");
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), "pd 10", "cmd + arg");
	r_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_args(void) {
	char *args[] = { "d", "0" };
	RCmdParsedArgs *a = r_cmd_parsed_args_new ("wA", 2, args);
	mu_assert_streq (a->argv[0], "wA", "wA is the command");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "d 0", "two args");
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), "wA d 0", "cmd + args");
	r_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_nospace(void) {
	char *args[] = { "dr*" };
	RCmdParsedArgs *a = r_cmd_parsed_args_new (".", 1, args);
	a->has_space_after_cmd = false;
	mu_assert_streq (a->argv[0], ".", ". is the command");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "dr*", "arg");
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), ".dr*", "cmd + args without space");
	r_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_newcmd(void) {
	RCmdParsedArgs *a = r_cmd_parsed_args_newcmd ("pd");
	mu_assert_streq (a->argv[0], "pd", "pd is the command");
	char *args[] = { "10" };
	bool res = r_cmd_parsed_args_setargs (a, 1, args);
	mu_assert ("args should be added", res);
	mu_assert_eq (a->argc, 2, "argc == 2");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "10", "arg");
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), "pd 10", "cmd + args");

	char *args2[] = { "2", "3" };
	res = r_cmd_parsed_args_setargs (a, 2, args2);
	mu_assert_eq (a->argc, 3, "argc == 3");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "2 3", "arg");
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), "pd 2 3", "cmd + args");

	r_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_newargs(void) {
	char *args[] = { "0", "1", "2" };
	RCmdParsedArgs *a = r_cmd_parsed_args_newargs (3, args);
	mu_assert_eq (a->argc, 4, "argc == 4");
	mu_assert_streq_free (r_cmd_parsed_args_argstr (a), "0 1 2", "args");
	mu_assert_streq (a->argv[1], "0", "first arg");
	mu_assert_streq (a->argv[2], "1", "second arg");

	bool res = r_cmd_parsed_args_setcmd (a, "pd");
	mu_assert ("cmd should be added", res);
	mu_assert_streq_free (r_cmd_parsed_args_execstr (a), "pd 0 1 2", "cmd + args");
	r_cmd_parsed_args_free (a);
	mu_end;
}

int all_tests() {
	mu_run_test (test_parsed_args_noargs);
	mu_run_test (test_parsed_args_onearg);
	mu_run_test (test_parsed_args_args);
	mu_run_test (test_parsed_args_nospace);
	mu_run_test (test_parsed_args_newcmd);
	mu_run_test (test_parsed_args_newargs);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
