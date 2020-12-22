#include <r_util.h>
#include "minunit.h"

bool test_r_base64_decode_dyn(void) {
	char* hello = (char*)r_base64_decode_dyn ("aGVsbG8=", -1);
	mu_assert_streq(hello, "hello", "base64_decode_dyn");
	free (hello);
	mu_end;
}

bool test_r_base64_decode(void) {
	ut8* hello = malloc (50);
	int status = r_base64_decode (hello, "aGVsbG8=", -1);
	mu_assert_eq (status, (int)strlen("hello"), "valid base64 decoding");
	mu_assert_streq((char*)hello, "hello", "base64 decoding");
	free (hello);
	mu_end;
}

bool test_r_base64_decode_invalid(void) {
	ut8* hello = malloc (50);
	int status = r_base64_decode (hello, "\x01\x02\x03\x04\x00", -1);
	// Returns the length of the decoded string, 0 == invalid input.
	mu_assert_eq(status, -1, "invalid base64 decoding");
	free (hello);
	mu_end;
}

int test_r_base64_encode_dyn(void) {
	char* hello = r_base64_encode_dyn("hello", -1);
	mu_assert_streq(hello, "aGVsbG8=", "base64_encode_dyn");
	free (hello);
	mu_end;
}

int test_r_base64_encode(void) {
	char* hello = malloc (50);
	r_base64_encode(hello, (ut8*)"hello", -1);
	mu_assert_streq(hello, "aGVsbG8=", "base64_encode_dyn");
	free (hello);
	mu_end;
}

int all_tests() {
	mu_run_test(test_r_base64_decode_dyn);
	mu_run_test(test_r_base64_decode);
	mu_run_test(test_r_base64_decode_invalid);
	mu_run_test(test_r_base64_encode_dyn);
	mu_run_test(test_r_base64_encode);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
