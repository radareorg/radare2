#include <r_util.h>
#include "minunit.h"

static bool test_bloom_binary(void) {
	const size_t bits[] = {19, 997, 1024, 4096};
	const size_t widths[] = {0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32};
	ut8 values[64][32];
	size_t i, j, m, w;
	for (i = 0; i < R_ARRAY_SIZE (values); i++) {
		for (j = 0; j < sizeof (values[i]); j++) {
			values[i][j] = (ut8)(i * 17 + j * 37);
		}
	}
	for (m = 0; m < R_ARRAY_SIZE (bits); m++) {
		for (w = 0; w < R_ARRAY_SIZE (widths); w++) {
			RBloom *bloom = r_bloom_new (bits[m], m + 2, NULL);
			mu_assert_notnull (bloom, "create bloom filter");
			for (i = 0; i < R_ARRAY_SIZE (values); i++) {
				r_bloom_add (bloom, values[i], widths[w]);
			}
			for (i = 0; i < R_ARRAY_SIZE (values); i++) {
				mu_assert_true (r_bloom_check (bloom, values[i], widths[w]), "no false negatives");
			}
			r_bloom_reset (bloom);
			for (i = 0; i < R_ARRAY_SIZE (values); i++) {
				mu_assert_false (r_bloom_check (bloom, values[i], widths[w]), "reset clears all bits");
			}
			r_bloom_add (bloom, values[0], widths[w]);
			mu_assert_true (r_bloom_check (bloom, values[0], widths[w]), "reuse after reset");
			r_bloom_free (bloom);
		}
	}
	mu_end;
}

static int custom_calls;

static ut32 custom_hash(const void *data, size_t len, ut32 seed) {
	custom_calls++;
	const ut8 *p = data;
	ut32 h = seed;
	size_t i;
	for (i = 0; i < len; i++) {
		h = h * 33 + p[i];
	}
	return h;
}

static bool test_bloom_custom(void) {
	RBloomHashFunc funcs[] = {custom_hash, custom_hash};
	RBloom *bloom = r_bloom_new (1024, R_ARRAY_SIZE (funcs), funcs);
	mu_assert_notnull (bloom, "create custom bloom filter");
	const ut8 bytes[] = {0, 255, 0, 128};
	custom_calls = 0;
	r_bloom_add (bloom, bytes, sizeof (bytes));
	mu_assert_eq (custom_calls, 2, "call both custom functions on add");
	mu_assert_true (r_bloom_check (bloom, bytes, sizeof (bytes)), "custom membership");
	mu_assert_eq (custom_calls, 4, "call both custom functions on check");
	r_bloom_reset (bloom);
	custom_calls = 0;
	r_bloom_add (bloom, bytes, sizeof (bytes));
	mu_assert_eq (custom_calls, 2, "reset preserves custom functions");
	mu_assert_true (r_bloom_check (bloom, bytes, sizeof (bytes)), "custom membership after reset");
	r_bloom_free (bloom);
	mu_end;
}

static bool test_bloom_distribution(void) {
	RBloom *bloom = r_bloom_new (4096, 4, NULL);
	mu_assert_notnull (bloom, "create distribution filter");
	char name[64];
	unsigned int i;
	for (i = 0; i < 128; i++) {
		snprintf (name, sizeof (name), "flag.common.prefix.%08x", i);
		r_bloom_add (bloom, name, strlen (name));
	}
	unsigned int positives = 0;
	for (; i < 1152; i++) {
		snprintf (name, sizeof (name), "flag.common.prefix.%08x", i);
		positives += r_bloom_check (bloom, name, strlen (name));
	}
	mu_assert_true (positives < 102, "shared prefixes must not saturate the filter");
	r_bloom_free (bloom);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_bloom_binary);
	mu_run_test (test_bloom_custom);
	mu_run_test (test_bloom_distribution);
	return tests_passed != tests_run;
}
