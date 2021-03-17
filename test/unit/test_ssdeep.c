#include <r_hash.h>
#include <r_util.h>
#include "minunit.h"

static const char *input_0 = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *input_1 = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXY_";
static const char *input_2 = "abcdefghijklmnopqrstuvwxyz01234567890______GHIJKLMNOPQRSTUVWXY_";

static const char *hash_0 = "1:EHGBADCNMPOJILKVUXWRQTSdcfVUXWRQTSdcVknmhgjitsvuporq1032xwzy98/n:EHGBADCNMPOJILKVUXWRQTSdcf+XXTSP";
static const char *hash_1 = "1:EHGBADCNMPOJILKVUXWRQTSdcfVUXWRQTSdcVknmhgjitsvuporq1032xwzy986n:uWmCNMPOJILKVUXWRQTSdcf+XXTSdcVT";
static const char *hash_2 = "hash2";

int test_ssdeep(void) {
	char *h0 = r_hash_ssdeep ((const ut8*)input_0, strlen (input_0));
	char *h1 = r_hash_ssdeep ((const ut8*)input_1, strlen (input_1));
	char *h2 = r_hash_ssdeep ((const ut8*)input_2, strlen (input_2));
	mu_assert_streq (h0, hash_0, "hash0 is fine");
	mu_assert_streq (h1, hash_1, "hash1 is fine");
	int distance = r_str_distance (h0, h1);
	mu_assert_eq (88, distance, "distance"); // 80% equal
	int distance2 = r_str_distance (h0, h0);
	mu_assert_eq (100, distance2, "distance2");
	int distance3 = r_str_distance (h0, "123");
	mu_assert_eq (2, distance3, "distance3");
	int distance4 = r_str_distance (h0, h2);
	mu_assert_eq (82, distance4, "distance4");
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
