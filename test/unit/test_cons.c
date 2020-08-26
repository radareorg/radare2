#include <r_cons.h>
#include "minunit.h"

bool test_r_cons() {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	r_cons_rgb_init();

	// all these strdup are for asan/valgrind to have some exact bounds to work with

	char *foo = strdup ("___"); // should crash in asan mode
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 0, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// old school
	foo = strdup ("\x1b[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("32mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 256
	foo = strdup ("\x1b[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 24 bit
	foo = strdup ("\x1b[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// no over-read
	foo = strdup ("38;2");
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("38;5");
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("3");
	r_cons_rgb_parse (foo, &r, &g, &b, &a);
	free (foo);

	mu_end;
}

bool test_cons_to_html() {
	char *html;

	html = r_cons_html_filter ("\x1b[32mhello\x1b[0m", NULL);
	mu_assert_streq_free (html, "<font color='#0f0'>hello</font>", "Simple font color");

	html = r_cons_html_filter ("\x1b[31mhello\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<font color='#f00'>hello</font>abc", "Simple font color2");

	html = r_cons_html_filter ("\x1b[31mhe\x1b[44mllo\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<font color='#f00'>he</font><font color='#f00' style='background-color:#00f'>llo</font>abc", "Color and background");

	html = r_cons_html_filter ("\x1b[44mhe\x1b[31mllo\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<font style='background-color:#00f'>he</font><font color='#f00' style='background-color:#00f'>llo</font>abc", "Background and color");

	html = r_cons_html_filter ("AA\x1b[31mBB\x1b[32mCC\x1b[0mDD", NULL);
	mu_assert_streq_free (html, "AA<font color='#f00'>BB</font><font color='#0f0'>CC</font>DD", "Switch color");

	html = r_cons_html_filter ("AA\x1b[31mBB\x1b[32m\x1b[41mCC\x1b[0mDD", NULL);
	mu_assert_streq_free (html, "AA<font color='#f00'>BB</font><font color='#0f0' style='background-color:#f00'>CC</font>DD", "Multiple changes");

	html = r_cons_html_filter ("\x1b[33m0x0005d01\x1b[0m \x1b[36mand\x1b[36m foo", NULL);
	mu_assert_streq_free (html, "<font color='#ff0'>0x0005d01</font>&nbsp;<font color='#aaf'>and</font><font color='#aaf'>&nbsp;foo</font>", "Space and reset");

	html = r_cons_html_filter ("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[0mCCC", NULL);
	mu_assert_streq_free (html, "<font color='#ff0'>AAAA</font>"
				    "<font color='#ff0' style='text-decoration:underline overline'>BBBB</font>"
				    "<font color='#ff0' style='text-decoration:underline overline'>BBB</font>CCC",
		"Invert");

	html = r_cons_html_filter ("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[27mCCC", NULL);
	mu_assert_streq_free (html, "<font color='#ff0'>AAAA</font>"
				    "<font color='#ff0' style='text-decoration:underline overline'>BBBB</font>"
				    "<font color='#ff0' style='text-decoration:underline overline'>BBB</font><font color='#ff0'>CCC</font>",
		"Invert rest");

	html = r_cons_html_filter ("\x1b[41m\x1b[31mBB\x1b[39mCC", NULL);
	mu_assert_streq_free (html, "<font color='#f00' style='background-color:#f00'>BB</font>"
		"<font style='background-color:#f00'>CC</font>", "Default font color color");

	html = r_cons_html_filter ("\x1b[41m\x1b[31mBB\x1b[49mCC", NULL);
	mu_assert_streq_free (html, "<font color='#f00' style='background-color:#f00'>BB</font><font color='#f00'>CC</font>", "Default background color");

	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_cons);
	mu_run_test (test_cons_to_html);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
