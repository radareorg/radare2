#include <r_util.h>
#include <r_util/r_print.h>
#include <r_cons.h>
#include "minunit.h"

static RStrBuf format_output;

static int capture_format_output(RCons *cons, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_strbuf_vappendf (&format_output, fmt, ap);
	va_end (ap);
	return 0;
}

bool test_r_print_bytes(void) {
	const ut8 buf[] = { 0x00, 0x12, 0xab };
	mu_assert_streq_free (r_print_bytes (NULL, buf, sizeof (buf), "%02x", ' '), "00 12 ab", "space separated bytes");
	mu_assert_streq_free (r_print_bytes (NULL, buf, sizeof (buf), "0x%02x", ','), "0x00,0x12,0xab", "comma separated bytes");
	mu_end;
}

bool test_r_print_bytes_single(void) {
	const ut8 buf[] = { 0xff };
	mu_assert_streq_free (r_print_bytes (NULL, buf, sizeof (buf), "%02x", ' '), "ff", "single byte without trailing separator");
	mu_end;
}

bool test_r_print_hexdump_strbuf(void) {
	const ut8 buf[] = { 0x00, 0x12, 0xab, 0xff };
	RPrint *print = r_print_new ();
	print->cols = sizeof (buf);
	print->flags &= ~R_PRINT_FLAGS_COLOR;
	RStrBuf sb;
	r_strbuf_init (&sb);
	r_print_hexdump_strbuf (print, &sb, 0x1000, buf, sizeof (buf), 16, 1, 1);
	const char *output = r_strbuf_get (&sb);
	mu_assert_notnull (strstr (output, "0x00001000"), "missing hexdump address");
	mu_assert_notnull (strstr (output, "0012 abff"), "missing hexdump bytes");
	r_strbuf_fini (&sb);
	r_print_free (print);
	mu_end;
}

bool test_r_print_format_without_console(void) {
	const ut8 buf[] = { 0x2a };
	RPrint *print = r_print_new ();
	RCons cons = { 0 };
	print->consb.cb_printf = capture_format_output;
	r_strbuf_init (&format_output);
	int i;
	for (i = 0; i < 2; i++) {
		print->consb.cons = i? &cons: NULL;
		r_print_format (print, 0x1000, buf, sizeof (buf), "b field", R_PRINT_MUSTSEE, NULL, NULL);
		mu_assert_streq (r_strbuf_get (&format_output), " field : 0x00001000 = 0x2a\n", "plain format without a console context");
		r_strbuf_set (&format_output, "");
		r_print_format (print, 0x1000, buf, sizeof (buf), "b field", R_PRINT_JSON, NULL, NULL);
		mu_assert_streq (r_strbuf_get (&format_output), "[{\"name\":\"field\",\"type\":\"b\",\"offset\":4096,\"value\":42}]\n", "JSON format without a console context");
		r_strbuf_set (&format_output, "");
		char field[] = "field";
		r_print_format (print, 0x1000, buf, sizeof (buf), "b field", R_PRINT_MUSTSET, "5", field);
		mu_assert_streq (r_strbuf_get (&format_output), "wx 05 @ 0x00001000\n", "set without a core prints the command");
		r_strbuf_set (&format_output, "");
	}
	r_strbuf_fini (&format_output);
	r_print_free (print);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_print_bytes);
	mu_run_test (test_r_print_bytes_single);
	mu_run_test (test_r_print_hexdump_strbuf);
	mu_run_test (test_r_print_format_without_console);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
