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

	// test with pre-initialized pointer
	ut8 *buf2 = NULL;
	len = r_hex_str2bin_until_new ("44", &buf2);
	mu_assert_eq (len, 1, "r_hex_str2bin_until_new simple 1-byte");
	free (buf2);

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

bool test_str2bin_dup(void) {
	size_t len = 0;

	// Test simple hexpairs
	ut8 *result1 = r_hex_str2bin_dup ("4ff2bafc", &len);
	mu_assert_notnull (result1, "Should parse hex string");
	mu_assert_eq (len, 4, "Should have 4 bytes");
	mu_assert_eq (result1[0], 0x4f, "First byte should be 0x4f");
	mu_assert_eq (result1[1], 0xf2, "Second byte should be 0xf2");
	mu_assert_eq (result1[2], 0xba, "Third byte should be 0xba");
	mu_assert_eq (result1[3], 0xfc, "Fourth byte should be 0xfc");
	free (result1);

	// Test hexpairs with spaces (r_hex_str2bin handles whitespace)
	ut8 *result2 = r_hex_str2bin_dup ("ff fe fd fc", &len);
	mu_assert_notnull (result2, "Should parse hex with spaces");
	mu_assert_eq (len, 4, "Should have 4 bytes");
	mu_assert_eq (result2[0], 0xff, "First byte should be 0xff");
	mu_assert_eq (result2[1], 0xfe, "Second byte should be 0xfe");
	free (result2);

	// Test NULL len parameter
	ut8 *result3 = r_hex_str2bin_dup ("aabb", NULL);
	mu_assert_notnull (result3, "Should work with NULL len");
	free (result3);

	// Test empty string
	ut8 *result4 = r_hex_str2bin_dup ("", &len);
	mu_assert_null (result4, "Should return NULL for empty string");

	// Test invalid hex
	ut8 *result5 = r_hex_str2bin_dup ("xyz", &len);
	mu_assert_null (result5, "Should return NULL for invalid hex");

	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_hex_from_c);
	mu_run_test (test_r_hex_from_py);
	mu_run_test (test_r_hex_from_code);
	mu_run_test (test_r_hex_no_code);
	mu_run_test (test_str2bin_alloc);
	mu_run_test (test_str2bin_dup);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
