#include <r_util.h>
#include "minunit.h"

bool test_punycode_encode_grows_output(void) {
	const ut8 input[] = {
		0xf0, 0x9f, 0x91, 0xa8, 0xe2, 0x80, 0x8d, 0xf0,
		0x9f, 0xa6, 0xb0, 0x20, 0xf0, 0x9f, 0x91, 0xa8,
		0xf0, 0x9f, 0x8f, 0xbf, 0xe7, 0x80, 0x8d, 0xf0,
		0x9f, 0xa6, 0xb0, 0x20, 0xf0, 0x9f, 0x91, 0xa8,
		0xe2, 0x80, 0xd5, 0x59, 0xc6, 0xd0, 0x00
	};
	const char expected[] = "  Y-g5a5310bpbaw666glu62a60acad233nea";
	int output_len = 0;
	char *output = r_punycode_encode (input, sizeof (input), &output_len);
	mu_assert_notnull (output, "punycode output");
	mu_assert_eq (output_len, sizeof (expected) - 1, "punycode output length");
	mu_assert_memeq ((const ut8 *)output, (const ut8 *)expected, output_len, "punycode output");
	free (output);
	mu_end;
}

bool test_punycode_encode_truncated_utf8(void) {
	const ut8 input[] = {
		0x74, 0xf7, 0xf7, 0xf7, 0xf7, 0xd7, 0xf6,
		0xf7, 0xf7, 0x10, 0xf7, 0xf7, 0x00
	};
	int output_len = 1;
	char *output = r_punycode_encode (input, sizeof (input), &output_len);
	mu_assert_null (output, "truncated UTF-8 input");
	mu_assert_eq (output_len, 0, "truncated UTF-8 output length");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_punycode_encode_grows_output);
	mu_run_test (test_punycode_encode_truncated_utf8);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
