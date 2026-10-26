#include <r_muta.h>
#include "minunit.h"

static bool test_sha2_unaligned_input(void) {
	const struct {
		const char *name;
		const char *digest;
	} algorithms[] = {
		{ "sha256", "e075f2f51cad23d0537186cfcd50f911ea954f9c2e32a437f45327f1b7899bbb" },
		{ "sha384", "3ce716af185561a09c41f48feae39232fd5fe96210778fc5b774a61d06990364026d10bea8c8a892f840bed42dfadc13" },
		{ "sha512", "b7828faae9bc9fa289a07a1be3f87cdc473014ea2697e5b1365b1b862b5c304c61390cbb795bfdd5ea67dd3f72ecf0976c27765729d2da5e630abca196ab29b8" },
	};
	ut8 input[263];
	memset (input, 'A', sizeof (input));
	RMuta *muta = r_muta_new ();
	size_t i, offset;
	for (i = 0; i < R_ARRAY_SIZE (algorithms); i++) {
		for (offset = 0; offset < 8; offset++) {
			RMutaResult result = r_muta_process_simple (muta, algorithms[i].name, input + offset, 256);
			mu_assert ("hash succeeds", result.success);
			mu_assert_streq (result.hex, algorithms[i].digest, "SHA-2 digest at every alignment");
			r_muta_result_free (&result);
		}
	}
	r_muta_free (muta);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_sha2_unaligned_input);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
