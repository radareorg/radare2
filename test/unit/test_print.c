#include <r_util.h>
#include <r_util/r_print.h>
#include "minunit.h"

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

bool all_tests(void) {
	mu_run_test (test_r_print_bytes);
	mu_run_test (test_r_print_bytes_single);
	mu_run_test (test_r_print_hexdump_strbuf);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
