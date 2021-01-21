#include <r_util.h>
#include "minunit.h"

bool test_r_hex_from_code() {
	const char *s;
	char *r;
	s = "char *s = \"ABCD\";";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"AB\" \"CD\";";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"\x41\x42\x43\x44\"";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"\x41\x42\" /* test */ \"\x43\x44\";";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"\n\r\033\"";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "0a0d1b", s);
	free (r);
	s = "uint8_t buffer[3] = {0x41, 0x42, 0x43, 0x44};";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "uint8_t buffer[3] = {0x41,\n0x42,\n0x43,\n0x44};";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "uint8_t buffer[3] = { 0x41 , \n 0x42, \n 0x43 , \n 0x44 } ;";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "uint8_t buffer[3] = {0x41, /* test */0x42, 0x43,/*test*/ 0x44};";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "buf = \"\x41\x42\x43\x44\"";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "buf = [0x41, 0x42, 0x43, 0x44]";
	r = r_hex_from_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);

	mu_end;
}

bool test_r_hex_from_c() {
	const char *s;
	char *r;
	s = "char *s = \"ABCD\";";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"AB\" \"CD\";";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"\x41\x42\x43\x44\"";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"\x41\x42\" /* test */ \"\x43\x44\";";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "char *s = \"\n\r\033\"";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "0a0d1b", s);
	free (r);
	s = "uint8_t buffer[3] = {0x41, 0x42, 0x43, 0x44};";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "uint8_t buffer[3] = {0x41,\n0x42,\n0x43,\n0x44};";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "uint8_t buffer[3] = { 0x41 , \n 0x42, \n 0x43 , \n 0x44 } ;";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "uint8_t buffer[3] = {0x41, /* test */0x42, 0x43,/*test*/ 0x44};";
	r = r_hex_from_c (s);
	mu_assert_streq (r, "41424344", s);
	free (r);

	mu_end;
}

bool test_r_hex_from_py() {
	const char *s;
	char *r;
	s = "s = \"ABCD\";";
	r = r_hex_from_py (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "s = \"\x41\x42\x43\x44\"";
	r = r_hex_from_py (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "s = \"\n\r\"";
	r = r_hex_from_py (s);
	mu_assert_streq (r, "0a0d", s);
	free (r);
	s = "buffer = [0x41, 0x42, 0x43, 0x44]";
	r = r_hex_from_py (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "buffer = [0x41,\n0x42,\n0x43,\n0x44]";
	r = r_hex_from_py (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "buffer = [ 0x41 , \n 0x42, \n 0x43 , \n 0x44 ]";
	r = r_hex_from_py (s);
	mu_assert_streq (r, "41424344", s);
	free (r);

	mu_end;
}

bool test_r_hex_no_code() {
	const char *s;
	char *r;
	s = "\"ABCD\"";
	r = r_hex_no_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "\"AB\" \"CD\"";
	r = r_hex_no_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "\"AB\"\n\"CD\"\n";
	r = r_hex_no_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "\"\x41\x42\x43\x44\"";
	r = r_hex_no_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);
	s = "\"\x41\x42\"  \"\x43\x44\";";
	r = r_hex_no_code (s);
	mu_assert_streq (r, "41424344", s);
	free (r);

	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_hex_from_c);
	mu_run_test (test_r_hex_from_py);
	mu_run_test (test_r_hex_from_code);
	mu_run_test (test_r_hex_no_code);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
