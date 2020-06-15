#include <r_cmd.h>
#include <r_cons.h>
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

static RCmdStatus afl_argv_handler(void *user, int argc, const char **argv) {
	return R_CMD_STATUS_OK;
}

bool test_cmd_descriptor_argv(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *cd = r_cmd_desc_argv_new (cmd, root, "afl", afl_argv_handler);
	mu_assert_notnull (cd, "cmddesc created");
	mu_assert_streq (cd->name, "afl", "command descriptor name is afl");
	mu_assert_eq (cd->type, R_CMD_DESC_TYPE_ARGV, "type of command descriptor is argv");
	mu_assert_ptreq (r_cmd_desc_parent (cd), root, "root parent descriptor");
	mu_assert_eq (root->n_children, 1, "root has 1 child");
	mu_assert_eq (cd->n_children, 0, "no children");
	r_cmd_free (cmd);
	mu_end;
}

bool test_cmd_descriptor_argv_nested(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *af_cd = r_cmd_desc_argv_new (cmd, root, "af", NULL);
	r_cmd_desc_argv_new (cmd, root, "af2", NULL);
	RCmdDesc *cd = r_cmd_desc_argv_new (cmd, af_cd, "afl", afl_argv_handler);
	mu_assert_ptreq (r_cmd_desc_parent (cd), af_cd, "parent of afl is af");
	mu_assert_true (r_pvector_contains (&af_cd->children, cd), "afl is child of af");
	r_cmd_free (cmd);
	mu_end;
}

static int a_oldinput_cb(void *user, const char *input) {
	return 0;
}

bool test_cmd_descriptor_oldinput(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *cd = r_cmd_desc_oldinput_new (cmd, root, "a", a_oldinput_cb);
	mu_assert_notnull (cd, "cmddesc created");
	mu_assert_streq (cd->name, "a", "command descriptor name is a");
	mu_assert_eq (cd->type, R_CMD_DESC_TYPE_OLDINPUT, "type of command descriptor is oldinput");
	mu_assert_ptreq (r_cmd_desc_parent (cd), root, "root parent descriptor");
	mu_assert_eq (cd->n_children, 0, "no children");
	r_cmd_free (cmd);
	mu_end;
}

static RCmdStatus ap_handler(void *user, int argc, const char **argv) {
	return R_CMD_STATUS_OK;
}

static RCmdStatus aeir_handler(void *user, int argc, const char **argv) {
	return R_CMD_STATUS_OK;
}

static int ae_handler(void *user, const char *input) {
	return 0;
}

static int w_handler(void *user, const char *input) {
	return 0;
}

bool test_cmd_descriptor_tree(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *a_cd = r_cmd_desc_argv_new (cmd, root, "a", NULL);
	r_cmd_desc_argv_new (cmd, a_cd, "ap", ap_handler);
	r_cmd_desc_oldinput_new (cmd, root, "w", w_handler);

	void **it_cd;
	r_cmd_desc_children_foreach (root, it_cd) {
		RCmdDesc *cd = *it_cd;
		mu_assert_ptreq (r_cmd_desc_parent (cd), root, "root is the parent");
	}

	r_cmd_free (cmd);
	mu_end;
}

bool test_cmd_get_desc(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *a_cd = r_cmd_desc_argv_new (cmd, root, "a", NULL);
	RCmdDesc *ap_cd = r_cmd_desc_argv_new (cmd, a_cd, "ap", ap_handler);
	RCmdDesc *apd_cd = r_cmd_desc_argv_new (cmd, ap_cd, "apd", ap_handler);
	RCmdDesc *ae_cd = r_cmd_desc_oldinput_new (cmd, a_cd, "ae", ae_handler);
	RCmdDesc *aeir_cd = r_cmd_desc_argv_new (cmd, a_cd, "aeir", aeir_handler);
	RCmdDesc *w_cd = r_cmd_desc_oldinput_new (cmd, root, "w", w_handler);

	mu_assert_null (r_cmd_get_desc (cmd, "afl"), "afl does not have any handler");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "ap"), ap_cd, "ap will be handled by ap");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "wx"), w_cd, "wx will be handled by w");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "wao"), w_cd, "wao will be handled by w");
	mu_assert_null (r_cmd_get_desc (cmd, "apx"), "apx does not have any handler");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "apd"), apd_cd, "apd will be handled by apd");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "ae"), ae_cd, "ae will be handled by ae");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "aeim"), ae_cd, "aeim will be handled by ae");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "aeir"), aeir_cd, "aeir will be handled by aeir");
	mu_assert_ptreq (r_cmd_get_desc (cmd, "aei"), ae_cd, "aei will be handled by ae");

	r_cmd_free (cmd);
	mu_end;
}

static RCmdStatus pd_handler(void *user, int argc, const char **argv) {
	mu_assert_eq (argc, 2, "pd_handler called with 2 arguments (name and arg)");
	mu_assert_streq (argv[0], "pd", "pd is argv[0]");
	mu_assert_streq (argv[1], "10", "10 is argv[1]");
	return R_CMD_STATUS_OK;
}

static RCmdStatus p_handler_argv(void *user, int argc, const char **argv) {
	return R_CMD_STATUS_OK;
}

static int p_handler(void *user, const char *input) {
	mu_assert_streq (input, "x 10", "input is +1");
	return -1;
}

static int px_handler(void *user, const char *input) {
	if (*input == '?') {
		r_cons_printf ("Free format px help\n");
	}
	return 0;
}

static int wv_handler(void *user, const char *input) {
	mu_assert_streq (input, "8 0xdeadbeef", "input is +2");
	return 1;
}

static int q_handler(void *user, const char *input) {
	return -2;
}

bool test_cmd_call_desc(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *p_cd = r_cmd_desc_argv_new (cmd, root, "p", NULL);
	r_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler);
	r_cmd_desc_oldinput_new (cmd, p_cd, "p", p_handler);
	r_cmd_desc_oldinput_new (cmd, root, "wv", wv_handler);
	r_cmd_desc_oldinput_new (cmd, root, "q", q_handler);

	char *pd_args[] = {"10"};
	char *px_args[] = {"10"};
	char *wv8_args[] = {"0xdeadbeef"};

	RCmdParsedArgs *a = r_cmd_parsed_args_new ("pd", 1, pd_args);
	mu_assert_eq(r_cmd_call_parsed_args (cmd, a), R_CMD_STATUS_OK, "pd was called correctly");
	r_cmd_parsed_args_free (a);

	a = r_cmd_parsed_args_new ("px", 1, px_args);
	mu_assert_eq(r_cmd_call_parsed_args (cmd, a), R_CMD_STATUS_INVALID, "p was called correctly");
	r_cmd_parsed_args_free (a);

	a = r_cmd_parsed_args_new ("wv8", 1, wv8_args);
	mu_assert_eq(r_cmd_call_parsed_args (cmd, a), R_CMD_STATUS_OK, "wv was called correctly");
	r_cmd_parsed_args_free (a);

	a = r_cmd_parsed_args_new ("quit", 0, NULL);
	mu_assert_eq (r_cmd_call_parsed_args (cmd, a), R_CMD_STATUS_EXIT, "quit is going to exit");
	r_cmd_parsed_args_free (a);

	r_cmd_free (cmd);
	mu_end;
}

bool test_cmd_help(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *p_cd = r_cmd_desc_argv_new (cmd, root, "p", NULL);
	RCmdDesc *pd_cd = r_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler);
	RCmdDesc *px_cd = r_cmd_desc_oldinput_new (cmd, p_cd, "px", px_handler);

	RCmdDescHelp p_help;
	r_cmd_desc_help_init (&p_help);
	p_help.summary = "p summary",
	p_help.usage = "p-usage",
	p_help.args_str = "",
	r_cmd_desc_set_help (p_cd, &p_help);

	RCmdDescHelp pd_help;
	r_cmd_desc_help_init (&pd_help);
	pd_help.usage = NULL;
	pd_help.summary = "pd summary";
	pd_help.args_str = "<num>";
	pd_help.description = "pd long description";
	RCmdDescExample pd_ex1 = { "pd 10", "print 10 disassembled instructions" };
	r_vector_push (&pd_help.examples, &pd_ex1);
	r_cmd_desc_set_help (pd_cd, &pd_help);

	RCmdDescHelp px_help;
	r_cmd_desc_help_init (&px_help);
	px_help.usage = "px-usage";
	px_help.summary = "px summary";
	px_help.args_str = "<verylongarg_str_num>";
	px_help.description = "px long description";
	r_cmd_desc_set_help (px_cd, &px_help);

	const char *p_help_exp = "Usage: p-usage   # p summary\n"
		"| pd <num>                 # pd summary\n"
		"| px <verylongarg_str_num> # px summary\n";
	RCmdParsedArgs *a = r_cmd_parsed_args_newcmd ("p?");
	char *h = r_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, p_help_exp, "wrong help for p?");
	free (h);
	r_cmd_parsed_args_free (a);

	const char *pd_help_exp = "Usage: pd <num>   # pd summary\n"
		"\npd long description\n"
		"\nExamples:\n"
		"| pd 10 # print 10 disassembled instructions\n";
	a = r_cmd_parsed_args_newcmd ("pd?");
	h = r_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, pd_help_exp, "wrong help for pd?");
	free (h);
	r_cmd_parsed_args_free (a);

	const char *pd_long_help_exp = "Usage: pd <num>   # pd summary\n"
		"\n"
		"pd long description\n"
		"\n"
		"Examples:\n"
		"| pd 10 # print 10 disassembled instructions\n";
	a = r_cmd_parsed_args_newcmd ("pd??");
	h = r_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, pd_long_help_exp, "wrong help for pd??");
	free (h);
	r_cmd_parsed_args_free (a);

	r_cmd_free (cmd);
	mu_end;
}

bool test_cmd_group_help(void) {
	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *p_cd = r_cmd_desc_argv_new (cmd, root, "p", p_handler_argv);
	RCmdDesc *pd_cd = r_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler);

	RCmdDescHelp p_help;
	r_cmd_desc_help_init (&p_help);
	p_help.group_summary = "p group-summary",
	p_help.summary = "p summary",
	p_help.usage = "p-usage",
	p_help.args_str = "",
	r_cmd_desc_set_help (p_cd, &p_help);

	RCmdDescHelp pd_help;
	r_cmd_desc_help_init (&pd_help);
	pd_help.summary = "pd summary",
	pd_help.args_str = "<num>",
	pd_help.description = "pd long description",
	r_cmd_desc_set_help (pd_cd, &pd_help);

	const char *p_help_exp = "Usage: p-usage   # p group-summary\n"
		"| p        # p summary\n"
		"| pd <num> # pd summary\n";
	RCmdParsedArgs *a = r_cmd_parsed_args_newcmd ("p?");
	char *h = r_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, p_help_exp, "wrong help for p?");
	free (h);
	r_cmd_parsed_args_free (a);

	r_cmd_free (cmd);
	mu_end;
}

bool test_cmd_oldinput_help(void) {
	r_cons_new ();

	RCmd *cmd = r_cmd_new ();
	RCmdDesc *root = r_cmd_get_root (cmd);
	RCmdDesc *p_cd = r_cmd_desc_argv_new (cmd, root, "p", NULL);
	r_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler);
	r_cmd_desc_oldinput_new (cmd, p_cd, "px", px_handler);

	RCmdParsedArgs *a = r_cmd_parsed_args_newcmd ("px?");
	const char *px_help_exp = "Free format px help\n";
	char *h = r_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, px_help_exp, "wrong help for px?");
	free (h);
	r_cmd_parsed_args_free (a);

	r_cmd_free (cmd);
	r_cons_free ();
	mu_end;
}

int all_tests() {
	mu_run_test (test_parsed_args_noargs);
	mu_run_test (test_parsed_args_onearg);
	mu_run_test (test_parsed_args_args);
	mu_run_test (test_parsed_args_nospace);
	mu_run_test (test_parsed_args_newcmd);
	mu_run_test (test_parsed_args_newargs);
	mu_run_test (test_cmd_descriptor_argv);
	mu_run_test (test_cmd_descriptor_argv_nested);
	mu_run_test (test_cmd_descriptor_oldinput);
	mu_run_test (test_cmd_descriptor_tree);
	mu_run_test (test_cmd_get_desc);
	mu_run_test (test_cmd_call_desc);
	mu_run_test (test_cmd_help);
	mu_run_test (test_cmd_group_help);
	mu_run_test (test_cmd_oldinput_help);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
