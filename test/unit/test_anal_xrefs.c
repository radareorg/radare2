#include <r_anal.h>
#include "minunit.h"

bool test_r_anal_xrefs_count(void) {
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

bool test_r_anal_purge_clears_xrefs(void) {
	RAnal *anal = r_anal_new ();

	mu_assert_true (r_anal_xrefs_set (anal, 0x1000, 0x2000, R_ANAL_REF_TYPE_CODE),
		"add xref before purge");
	mu_assert_eq (r_anal_xrefs_count (anal), 1, "xref exists before purge");

	r_anal_purge (anal);
	mu_assert_eq (r_anal_xrefs_count (anal), 0, "purge clears xrefs");
	mu_assert_true (r_anal_xrefs_set (anal, 0x3000, 0x4000, R_ANAL_REF_TYPE_CALL),
		"xref manager remains usable after purge");
	mu_assert_eq (r_anal_xrefs_count (anal), 1, "xref added after purge");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_xref_del_missing_edge(void) {
	RAnal *anal = r_anal_new ();

	r_anal_xrefs_set (anal, 0x1000, 0x2000, R_ANAL_REF_TYPE_CODE);
	r_anal_xref_del (anal, 0x1000, 0x3000);
	RVecAnalRef *refs = r_anal_refs_get (anal, 0x1000);
	mu_assert_notnull (refs, "deleting a missing edge keeps the only edge of its source");
	mu_assert_eq (RVecAnalRef_length (refs), 1, "one ref left");
	mu_assert_eq (RVecAnalRef_at (refs, 0)->addr, 0x2000, "the ref still points at its target");
	RVecAnalRef_free (refs);

	r_anal_xref_del (anal, 0x1000, 0x2000);
	mu_assert_null (r_anal_refs_get (anal, 0x1000), "deleting the edge removes it");
	mu_assert_eq (r_anal_xrefs_count (anal), 0, "no xrefs left");

	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_anal_xrefs_count);
	mu_run_test (test_r_anal_purge_clears_xrefs);
	mu_run_test (test_r_anal_xref_del_missing_edge);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
