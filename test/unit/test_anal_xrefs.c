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

bool test_r_anal_xrefs_gen_follows_edge_set(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "f", 0x1000, 0, NULL);
	mu_assert_notnull (fcn, "create function");

	r_anal_xrefs_set (anal, 0x2000, 0x1000, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 1, "one xref");
	const ut64 gen = fcn->meta.refsgen;

	r_anal_xrefs_set (anal, 0x2000, 0x1000, R_ANAL_REF_TYPE_CALL);
	r_anal_xref_del (anal, 0x3000, 0x1000);
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 1, "still one xref");
	mu_assert_eq (fcn->meta.refsgen, gen, "a write that changes no edge keeps the cached counts");

	r_anal_xrefs_set (anal, 0x2000, 0x1000, R_ANAL_REF_TYPE_CODE);
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 1, "retyped xref");
	mu_assert_true (fcn->meta.refsgen != gen, "retyping an edge invalidates the cached counts");

	const ut64 gen2 = fcn->meta.refsgen;
	r_anal_xref_del (anal, 0x2000, 0x1000);
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 0, "xref removed");
	mu_assert_true (fcn->meta.refsgen != gen2, "removing an edge invalidates the cached counts");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_xrefs_init_keeps_counts_stale(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "f", 0x1000, 0, NULL);
	mu_assert_notnull (fcn, "create function");

	r_anal_xrefs_set (anal, 0x2000, 0x1000, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 1, "one xref");
	const ut64 gen = fcn->meta.refsgen;

	// walk the new manager up to the generation the count was cached at: a
	// manager that restarted its generation would now serve that stale count
	r_anal_xrefs_init (anal);
	ut64 i;
	for (i = 1; i < gen; i++) {
		r_anal_xrefs_set (anal, 0x3000 + i, 0x4000, R_ANAL_REF_TYPE_DATA);
	}
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 0, "the reset dropped the xref");

	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_anal_xrefs_count);
	mu_run_test (test_r_anal_purge_clears_xrefs);
	mu_run_test (test_r_anal_xref_del_missing_edge);
	mu_run_test (test_r_anal_xrefs_gen_follows_edge_set);
	mu_run_test (test_r_anal_xrefs_init_keeps_counts_stale);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
