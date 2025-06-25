#include <r_cons.h>
#include "minunit.h"

bool test_r_cons(void) {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	r_cons_rgb_init();

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

#if 0
	// TODO: bring back those tests after constifying the colortable
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
#endif

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

	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_cons);
	mu_run_test (test_cons_to_html);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
