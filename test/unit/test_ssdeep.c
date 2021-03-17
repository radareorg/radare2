#include <r_hash.h>
#include <r_util.h>
#include "minunit.h"

static const char *input_0 = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *input_1 = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXY_";
static const char *input_2 = "abcdefghijklmnopqrstuvwxyz01234567890______GHIJKLMNOPQRSTUVWXY_";

static const char *hash_0 = "1:EHGBADCNMPOJILKVUXWRQTSdcfVUXWRQTSdcVknmhgjitsvuporq1032xwzy98/n:EHGBADCNMPOJILKVUXWRQTSdcf+XXTSP";
static const char *hash_1 = "1:EHGBADCNMPOJILKVUXWRQTSdcfVUXWRQTSdcVknmhgjitsvuporq1032xwzy986n:uWmCNMPOJILKVUXWRQTSdcf+XXTSdcVT";
static const char *hash_2 = "1:EHGBADCNMPOJILKVUXWRQTSdcfVUXWRQTSdcV666666itsvuporq1032xwzy986n:uWmCNMPOJILKVUXWRQTSdcf+XXTSdcVE";

int test_ssdeep(void) {
#define d r_str_distance
	char *h0 = r_hash_ssdeep ((const ut8*)input_0, strlen (input_0));
	char *h1 = r_hash_ssdeep ((const ut8*)input_1, strlen (input_1));
	char *h2 = r_hash_ssdeep ((const ut8*)input_2, strlen (input_2));
	mu_assert_streq (h0, hash_0, "hash0 is fine");
	mu_assert_streq (h1, hash_1, "hash1 is fine");
	mu_assert_streq (h2, hash_2, "hash2 is fine");
	mu_assert_eq (100, d(h0, h0), "distance2");
	mu_assert_eq (88, d(h0, h1), "distance"); // 80% equal
	mu_assert_eq (82, d(h0, h2), "distance4");
	mu_assert_eq (88, d(h1, h0), "distance5");
	mu_assert_eq (100, d(h1, h1), "distance6");
	mu_assert_eq (92, d(h1, h2), "distance6");
	mu_assert_eq (92, d(h2, h1), "distance6");
	mu_assert_eq (2, d(h0, "123"), "distance3");
	free (h0);
	free (h1);
	free (h2);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_ssdeep);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
