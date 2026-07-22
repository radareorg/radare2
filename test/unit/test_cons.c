#include <r_cons.h>
#include <r_util/r_time.h>
#include "minunit.h"

bool test_r_cons(void) {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	// all these strdup are for asan/valgrind to have some exact bounds to work with

	char *foo = strdup ("___"); // should crash in asan mode
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 0, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// old school
	foo = strdup ("\x1b[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("32mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 256
	foo = strdup ("\x1b[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 24 bit
	foo = strdup ("\x1b[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// no over-read
	foo = strdup ("38;2");
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("38;5");
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("3");
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	mu_end;
}

bool test_cons_to_html(void) {
	char *html;

	html = r_str_html_strip ("\x1b[32mhello\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='color:#0f0'>hello</span>", "Simple font color");

	html = r_str_html_strip ("\x1b[31mhello\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00'>hello</span>abc", "Simple font color2");

	html = r_str_html_strip ("\x1b[31mhe\x1b[44mllo\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00'>he</span><span style='color:#f00;background-color:#00f'>llo</span>abc", "Color and background");

	html = r_str_html_strip ("\x1b[44mhe\x1b[31mllo\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<span style='background-color:#00f'>he</span><span style='color:#f00;background-color:#00f'>llo</span>abc", "Background and color");

	html = r_str_html_strip ("AA\x1b[31mBB\x1b[32mCC\x1b[0mDD", NULL);
	mu_assert_streq_free (html, "AA<span style='color:#f00'>BB</span><span style='color:#0f0'>CC</span>DD", "Switch color");

	html = r_str_html_strip ("AA\x1b[31mBB\x1b[32m\x1b[41mCC\x1b[0mDD", NULL);
	mu_assert_streq_free (html, "AA<span style='color:#f00'>BB</span><span style='color:#0f0;background-color:#f00'>CC</span>DD", "Multiple changes");

	html = r_str_html_strip ("\x1b[33m0x0005d01\x1b[0m \x1b[36mand\x1b[36m foo", NULL);
	mu_assert_streq_free (html, "<span style='color:#ff0'>0x0005d01</span>&nbsp;<span style='color:#aaf'>and</span><span style='color:#aaf'>&nbsp;foo</span>", "Space and reset");

	html = r_str_html_strip ("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[0mCCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#ff0'>AAAA</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBBB</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBB</span>CCC",
		"Invert");

	html = r_str_html_strip ("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[27mCCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#ff0'>AAAA</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBBB</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBB</span><span style='color:#ff0'>CCC</span>",
		"Invert rest");

	html = r_str_html_strip ("\x1b[41m\x1b[31mBB\x1b[39mCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;background-color:#f00'>BB</span>"
		"<span style='background-color:#f00'>CC</span>", "Default font color color");

	html = r_str_html_strip ("\x1b[41m\x1b[31mBB\x1b[49mCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;background-color:#f00'>BB</span><span style='color:#f00'>CC</span>", "Default background color");

	// standalone bold
	html = r_str_html_strip ("\x1b[1mBOLD\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='font-weight:bold'>BOLD</span>", "Standalone bold");

	// bold + separate color
	html = r_str_html_strip ("\x1b[1m\x1b[31mBOLD\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;font-weight:bold'>BOLD</span>", "Bold then color");

	// bold prefix in combined sequence
	html = r_str_html_strip ("\x1b[1;31mBOLD\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;font-weight:bold'>BOLD</span>", "Bold combined with color");

	mu_end;
}

bool test_cons_context_clone_null(void) {
	RConsContext *ctx = r_cons_context_clone (NULL);
	mu_assert_null (ctx, "r_cons_context_clone(NULL) must return NULL");
	mu_end;
}

bool test_cons_timeout_keeps_earliest_deadline(void) {
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "r_cons_new2()");

	r_cons_break_timeout (cons, 10);
	const ut64 first_deadline = cons->timeout;
	mu_assert ("first timeout set", first_deadline > 0);

	r_cons_break_timeout (cons, 100);
	mu_assert_eq (cons->timeout, first_deadline, "longer nested timeout must not extend deadline");

	r_cons_break_timeout (cons, 1);
	mu_assert ("shorter nested timeout must tighten deadline", cons->timeout < first_deadline);

	r_cons_free (cons);
	mu_end;
}

bool test_cons_timeout_does_not_restart_expired_deadline(void) {
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "r_cons_new2()");

	cons->timeout = r_time_now_mono () - 1;
	cons->otimeout = 1;
	r_cons_break_timeout (cons, 100);
	mu_assert ("expired timeout must stay expired", cons->timeout < r_time_now_mono ());

	r_cons_free (cons);
	mu_end;
}

bool test_cons_json_path_grep_buffer(void) {
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "r_cons_new2()");

	const char *json = "{\"name\":\"radare2\"}\n";
	mu_assert ("write json", r_cons_write (cons, json, strlen (json)));
	cons->context->grep.json = true;
	cons->context->grep.json_path = strdup ("name");
	r_cons_grepbuf (cons);
	mu_assert_streq (cons->context->buffer, "radare2\n", "JSON path result");
	mu_assert_null (cons->context->grep.json_path, "JSON path must be released");

	r_cons_reset (cons);
	mu_assert ("write json again", r_cons_write (cons, json, strlen (json)));
	char *buffer = cons->context->buffer;
	cons->context->grep.json = true;
	cons->context->grep.json_path = strdup ("missing");
	r_cons_grepbuf (cons);
	mu_assert_ptreq (cons->context->buffer, buffer, "missing JSON path must preserve buffer");
	mu_assert_streq (cons->context->buffer, json, "missing JSON path contents");

	r_cons_free (cons);
	mu_end;
}

bool test_cons_grep_icase_does_not_mutate_word(void) {
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "r_cons_new2()");

	r_cons_grep_expression (cons, "+FoO");
	RConsGrepWord *gw = r_list_first (cons->context->grep.strings);
	mu_assert_notnull (gw, "grep word");
	char line[] = "foo";
	mu_assert_eq (r_cons_grep_line (cons, line, 3), 3, "case-insensitive grep");
	mu_assert_streq (gw->str, "FoO", "grep matching must not mutate words");

	r_cons_free (cons);
	mu_end;
}

static const RCoreHelpMessage test_help_message = {
	"Usage: h", "", "help test",
	"ha", "", "first command",
	"hab", "", "second command",
	NULL
};

bool test_cons_cmd_help_uses_context_color(void) {
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "r_cons_new2()");

	r_cons_cmd_help (cons, test_help_message);
	mu_assert_notnull (cons->context->buffer, "plain help output");
	mu_assert_null (strstr (cons->context->buffer, "\x1b["), "disabled color mode must not emit ANSI");

	r_cons_reset (cons);
	cons->context->color_mode = COLOR_MODE_16;
	r_cons_pal_reload (cons);
	r_cons_cmd_help (cons, test_help_message);
	mu_assert_notnull (strstr (cons->context->buffer, "\x1b["), "enabled color mode must emit ANSI");

	r_cons_push (cons);
	mu_assert_eq (cons->context->color_mode, COLOR_MODE_16, "child context must inherit color mode");
	r_cons_cmd_help (cons, test_help_message);
	mu_assert_notnull (strstr (cons->context->buffer, "\x1b["), "child help must use inherited color mode");
	r_cons_pop (cons);

	r_cons_free (cons);
	mu_end;
}

bool test_cons_cmd_help_match(void) {
	RCons *cons = r_cons_new2 ();
	mu_assert_notnull (cons, "r_cons_new2()");

	mu_assert_eq (r_cons_cmd_help_match (cons, test_help_message, "ha", 0, true), 1, "exact help match");
	mu_assert_notnull (strstr (cons->context->buffer, "first command"), "exact match output");
	mu_assert_null (strstr (cons->context->buffer, "second command"), "exact match must exclude longer commands");

	r_cons_reset (cons);
	mu_assert_eq (r_cons_cmd_help_match (cons, test_help_message, "ha", 0, false), 2, "contains help match");
	mu_assert_notnull (strstr (cons->context->buffer, "first command"), "contains first match");
	mu_assert_notnull (strstr (cons->context->buffer, "second command"), "contains second match");

	r_cons_reset (cons);
	mu_assert_eq (r_cons_cmd_help_match (cons, test_help_message, "ha", 'b', true), 1, "spec help match");
	mu_assert_null (strstr (cons->context->buffer, "first command"), "spec match must exclude base command");
	mu_assert_notnull (strstr (cons->context->buffer, "second command"), "spec match output");

	r_cons_free (cons);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_cons);
	mu_run_test (test_cons_to_html);
	mu_run_test (test_cons_context_clone_null);
	mu_run_test (test_cons_timeout_keeps_earliest_deadline);
	mu_run_test (test_cons_timeout_does_not_restart_expired_deadline);
	mu_run_test (test_cons_json_path_grep_buffer);
	mu_run_test (test_cons_grep_icase_does_not_mutate_word);
	mu_run_test (test_cons_cmd_help_uses_context_color);
	mu_run_test (test_cons_cmd_help_match);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
