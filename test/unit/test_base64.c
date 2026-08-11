#include <r_util.h>
#include "minunit.h"

bool test_r_base64_decode_dyn(void) {
	char* hello = (char*)r_base64_decode_dyn ("aGVsbG8=", -1, NULL, false);
	mu_assert_streq (hello, "hello", "base64_decode_dyn");
	free (hello);
	int olen = 0;
	hello = (char*)r_base64_decode_dyn ("aGVsbG8=", -1, &olen, true);
	mu_assert_streq (hello, "hello", "strict base64_decode_dyn");
	mu_assert_eq (olen, 5, "strict base64_decode_dyn length");
	free (hello);
	// strict mode fails on invalid input
	hello = (char*)r_base64_decode_dyn ("aGVs bG8=", -1, &olen, true);
	mu_assert_null (hello, "strict base64_decode_dyn invalid input");
	mu_assert_eq (olen, 0, "strict base64_decode_dyn invalid length");
	// tolerant mode recovers unpadded input
	hello = (char*)r_base64_decode_dyn ("aGVsbG8", -1, &olen, false);
	mu_assert_streq (hello, "hello", "tolerant unpadded base64_decode_dyn");
	mu_assert_eq (olen, 5, "tolerant unpadded base64_decode_dyn length");
	free (hello);
	mu_end;
}

bool test_r_base64_decode(void) {
	ut8* hello = malloc (50);
	int status = r_base64_decode (hello, "aGVsbG8=", -1, false);
	mu_assert_eq (status, (int)strlen ("hello"), "valid base64 decoding");
	mu_assert_streq((char*)hello, "hello", "base64 decoding");
	status = r_base64_decode (hello, "aGVsbG8=", -1, true);
	mu_assert_eq (status, (int)strlen ("hello"), "valid strict base64 decoding");
	mu_assert_streq((char*)hello, "hello", "strict base64 decoding");
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
	// lenient drops a lone trailing character
	status = r_base64_decode (hello, "a", -1, false);
	mu_assert_eq (status, 0, "lenient short base64 returns 0");
	free (hello);
	mu_end;
}

bool test_r_base64_decode_tail_invalid(void) {
	ut8* hello = malloc (16);
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

bool test_r_base64_decode_tolerant(void) {
	ut8* buf = malloc (32);
	// newlines and junk inside the stream are skipped, not truncated
	int status = r_base64_decode (buf, "aGVs\nbG8=", -1, false);
	mu_assert_eq (status, 5, "tolerant multiline base64 length");
	mu_assert_streq ((char *)buf, "hello", "tolerant multiline base64 output");
	status = r_base64_decode (buf, "aG!V@sb #G8=", -1, false);
	mu_assert_eq (status, 5, "tolerant junk-embedded base64 length");
	mu_assert_streq ((char *)buf, "hello", "tolerant junk-embedded base64 output");
	// unpadded tail groups are recovered
	status = r_base64_decode (buf, "aGVsbG8", -1, false);
	mu_assert_eq (status, 5, "tolerant unpadded base64 length");
	mu_assert_streq ((char *)buf, "hello", "tolerant unpadded base64 output");
	// concatenated padded chunks all decode
	status = r_base64_decode (buf, "aGVsbG8=aGVsbG8=", -1, false);
	mu_assert_eq (status, 10, "tolerant concatenated base64 length");
	mu_assert_streq ((char *)buf, "hellohello", "tolerant concatenated base64 output");
	free (buf);
	mu_end;
}

bool test_r_base64_decode_strict(void) {
	ut8* buf = malloc (16);
	// whitespace is not valid in strict mode
	int status = r_base64_decode (buf, "aGVs bG8=", -1, true);
	mu_assert_eq (status, -1, "strict embedded space rejected");
	// padding in the middle of the stream is rejected
	status = r_base64_decode (buf, "aG==aGVs", -1, true);
	mu_assert_eq (status, -1, "strict mid-stream padding rejected");
	// padding cannot be followed by more data in the last group
	status = r_base64_decode (buf, "aG=s", -1, true);
	mu_assert_eq (status, -1, "strict data after padding rejected");
	// at most two padding characters
	status = r_base64_decode (buf, "a===", -1, true);
	mu_assert_eq (status, -1, "strict overlong padding rejected");
	// proper double padding decodes a single byte
	status = r_base64_decode (buf, "aQ==", -1, true);
	mu_assert_eq (status, 1, "strict double padding length");
	mu_assert_streq ((char *)buf, "i", "strict double padding output");
	// url-safe alphabet is accepted
	status = r_base64_decode (buf, "-_-_", -1, true);
	mu_assert_eq (status, 3, "strict url-safe length");
	mu_assert_memeq (buf, (const ut8 *)"\xfb\xff\xbf", 3, "strict url-safe output");
	free (buf);
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
	mu_run_test (test_r_base64_decode_tolerant);
	mu_run_test (test_r_base64_decode_strict);
	mu_run_test (test_r_base64_encode_dyn);
	mu_run_test (test_r_base64_encode);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
