#include <r_util.h>
#include "minunit.h"

bool test_r_hex_from_code(void) {
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

bool test_r_hex_from_c(void) {
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

bool test_r_hex_from_py(void) {
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

bool test_r_hex_no_code(void) {
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

bool test_str2bin_alloc (void) {
	R_ALIGNED(8) ut8 *buf = NULL;
	int len;

	// bad strings
	len = r_hex_str2bin_until_new ("4", &buf);
	mu_assert_eq (len, 0, "r_hex_str2bin_until_new invalid str 1");
	mu_assert_null (buf, "r_hex_str2bin_until_new invalid str 1");

	len = r_hex_str2bin_until_new ("444:", &buf);
	mu_assert_eq (len, 0, "r_hex_str2bin_until_new invalid str 2");
	mu_assert_null (buf, "r_hex_str2bin_until_new invalid str 2");

	len = r_hex_str2bin_until_new (" 4444", &buf);
	mu_assert_eq (len, 0, "r_hex_str2bin_until_new invalid str 3");
	mu_assert_null (buf, "r_hex_str2bin_until_new invalid str 3");

	len = r_hex_str2bin_until_new ("", &buf);
	mu_assert_eq (len, 0, "r_hex_str2bin_until_new invalid str 4");
	mu_assert_null (buf, "r_hex_str2bin_until_new invalid str 4");

	// bad bufs
	R_ALIGNED(8) ut8 buf2[8];
	len = r_hex_str2bin_until_new ("44", (ut8 **)&buf2);
	mu_assert_eq (len, 1, "r_hex_str2bin_until_new accepted non-null **");

	// valid input
	buf = NULL;
	len = r_hex_str2bin_until_new ("4142", &buf);
	mu_assert_eq (len, 2, "r_hex_str2bin_until_new simple example");
	mu_assert_notnull (buf, "r_hex_str2bin_until_new simple example");
	mu_assert_memeq (buf, (ut8 *)"\x41\x42", len, "r_hex_str2bin_until_new simple example");
	free (buf);

	buf = NULL;
	len = r_hex_str2bin_until_new ("414243:NOT_HEX", &buf);
	mu_assert_eq (len, 3, "r_hex_str2bin_until_new \"414243:NOT_HEX\" returns 3 bytes");
	mu_assert_notnull (buf, "r_hex_str2bin_until_new \"414243:NOT_HEX\" returns 3 bytes");
	mu_assert_memeq (buf, (ut8 *)"\x41\x42\x43", len, "r_hex_str2bin_until_new \"414243:NOT_HEX\" returns 3 bytes");
	free (buf);

	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_hex_from_c);
	mu_run_test (test_r_hex_from_py);
	mu_run_test (test_r_hex_from_code);
	mu_run_test (test_r_hex_no_code);
	mu_run_test (test_str2bin_alloc);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
