#include <r_anal.h>
#include "minunit.h"

bool test_r_anal_xrefs_count() {
	RAnal *anal = r_anal_new ();

	mu_assert_eq (r_anal_xrefs_count (anal), 0, "xrefs count");

	r_anal_xrefs_set (anal, 0x1337, 42, R_ANAL_REF_TYPE_NULL);
	r_anal_xrefs_set (anal, 0x1337, 43, R_ANAL_REF_TYPE_CODE);
	r_anal_xrefs_set (anal, 1234, 43, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 12345, 43, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 4321, 4242, R_ANAL_REF_TYPE_CALL);

	mu_assert_eq (r_anal_xrefs_count (anal), 5, "xrefs count");

	r_anal_free (anal);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_anal_xrefs_count);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
