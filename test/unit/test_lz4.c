#include <r_util.h>
#include "minunit.h"

bool test_lz4_literal_lengths(void) {
	const int lengths[] = { 14, 15, 270, 525 };
	ut8 input[544], output[530];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (lengths); i++) {
		const int run = lengths[i];
		memcpy (input, "\x10" "A\x01\x00", 4);
		int size = 4;
		input[size++] = R_MIN (run, 15) << 4;
		if (run >= 15) {
			int left = run - 15;
			while (left >= 255) {
				input[size++] = 255;
				left -= 255;
			}
			input[size++] = left;
		}
		memset (input + size, 'B', run);
		size += run;
		int written = 0;
		mu_assert_eq (r_lz4_decompress_block (input, size, &written, output, run + 5), 0, "valid literal run");
		mu_assert_eq (written, run + 5, "exact output size");
		mu_assert_memeq (output, (const ut8 *)"AAAAA", 5, "overlapping match before literals");
		mu_assert_memeq (output + 5, input + size - run, run, "literal bytes");
		mu_assert_eq (r_lz4_decompress_block (input, size, &written, output, 5), -1, "no room for literals");
		mu_assert_eq (r_lz4_decompress_block (input, size, &written, output, run + 4), -1, "short output");
		mu_assert_eq (r_lz4_decompress_block (input, size - 1, &written, output, run + 5), -1, "short input");
	}
	mu_end;
}

bool test_lz4_literal_overflow(void) {
	// 15 + 255 * 16843008 + 240 wraps a 32-bit literal length to -1.
	const int extensions = 16843008;
	const int size = extensions + 6;
	ut8 *input = malloc (size);
	mu_assert_notnull (input, "allocate overflow input");
	memcpy (input, "\x10" "A\x01\x00\xf0", 5);
	memset (input + 5, 255, extensions);
	input[size - 1] = 240;
	ut8 output[4096];
	int written = 0;
	const int result = r_lz4_decompress_block (input, size, &written, output, sizeof (output));
	free (input);
	mu_assert_eq (result, -1, "reject overflowing literal length");
	mu_end;
}

bool test_lz4_match_copy_exact_end(void) {
	const ut8 input[] = {
		0xe0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0xad, 0xde, 0xef, 0xbe, 0x04,
		0x00, 0x0f, 0x04, 0x00, 0x4f, 0x00, 0x04, 0x00
	};
	ut8 output[128];
	int written = 0;
	memset (output, 0xcc, sizeof (output));
	mu_assert_eq (r_lz4_decompress_block ((ut8 *)input, sizeof (input), &written, output, 120), 0, "valid match copy");
	mu_assert_eq (written, 120, "exact match output size");
	size_t i;
	for (i = 120; i < sizeof (output); i++) {
		mu_assert_eq (output[i], 0xcc, "match copy stays inside output size");
	}
	mu_assert_eq (r_lz4_decompress_block ((ut8 *)input, sizeof (input), &written, output, 119), -1, "short output");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_lz4_literal_lengths);
	mu_run_test (test_lz4_literal_overflow);
	mu_run_test (test_lz4_match_copy_exact_end);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
