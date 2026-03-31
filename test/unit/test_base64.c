#include <r_util.h>
#include "minunit.h"

bool test_r_base64_decode_dyn(void) {
	char* hello = (char*)r_base64_decode_dyn ("aGVsbG8=", -1, NULL);
	mu_assert_streq (hello, "hello", "base64_decode_dyn");
	free (hello);
	mu_end;
}

bool test_r_base64_decode(void) {
	ut8* hello = malloc (50);
	int status = r_base64_decode (hello, "aGVsbG8=", -1, false);
	mu_assert_eq (status, (int)strlen ("hello"), "valid base64 decoding");
	mu_assert_streq((char*)hello, "hello", "base64 decoding");
	free (hello);
	mu_end;
}

bool test_r_base64_decode_invalid(void) {
	ut8* hello = malloc (50);
	// strict rejects invalid characters
	int status = r_base64_decode (hello, "\x01\x02\x03\x04\x00", -1, true);
	mu_assert_eq (status, -1, "strict invalid base64 decoding");
	// lenient returns 0 decoded bytes
	status = r_base64_decode (hello, "\x01\x02\x03\x04\x00", -1, false);
	mu_assert_eq (status, 0, "lenient invalid base64 decoding");
	free (hello);
	mu_end;
}

bool test_r_base64_decode_empty(void) {
	ut8* hello = malloc (1);
	int status = r_base64_decode (hello, "", -1, false);
	mu_assert_eq (status, 0, "empty base64 decoding");
	mu_assert_streq ((char *)hello, "", "empty base64 output");
	free (hello);
	mu_end;
}

bool test_r_base64_decode_short_invalid(void) {
	ut8* hello = malloc (8);
	// strict rejects non-multiple-of-4 length
	int status = r_base64_decode (hello, "a", -1, true);
	mu_assert_eq (status, -1, "strict short base64 decoding");
	// lenient returns 0 decoded bytes
	status = r_base64_decode (hello, "a", -1, false);
	mu_assert_eq (status, 0, "lenient short base64 returns 0");
	free (hello);
	mu_end;
}

bool test_r_base64_decode_tail_invalid(void) {
	ut8* hello = malloc (8);
	// strict rejects trailing garbage
	int status = r_base64_decode (hello, "aGVsbG8=x", -1, true);
	mu_assert_eq (status, -1, "strict tail garbage rejected");
	// lenient decodes valid part
	status = r_base64_decode (hello, "aGVsbG8=x", -1, false);
	mu_assert_eq (status, 5, "lenient tail garbage ignored");
	mu_assert_streq ((char *)hello, "hello", "lenient tail garbage output");
	free (hello);
	mu_end;
}

int test_r_base64_encode_dyn(void) {
	char* hello = r_base64_encode_dyn ((const ut8*)"hello", -1);
	mu_assert_streq (hello, "aGVsbG8=", "base64_encode_dyn");
	free (hello);
	mu_end;
}

int test_r_base64_encode(void) {
	char* hello = malloc (50);
	r_base64_encode (hello, (ut8*)"hello", -1);
	mu_assert_streq (hello, "aGVsbG8=", "base64_encode_dyn");
	free (hello);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_base64_decode_dyn);
	mu_run_test (test_r_base64_decode);
	mu_run_test (test_r_base64_decode_invalid);
	mu_run_test (test_r_base64_decode_empty);
	mu_run_test (test_r_base64_decode_short_invalid);
	mu_run_test (test_r_base64_decode_tail_invalid);
	mu_run_test (test_r_base64_encode_dyn);
	mu_run_test (test_r_base64_encode);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
