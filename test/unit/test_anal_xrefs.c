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

bool test_r_anal_function_count_refs_sees_added_block(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "f", 0x1000, 0, NULL);
	mu_assert_notnull (fcn, "create function");
	r_anal_xrefs_set (anal, 0x1000, 0x2000, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (r_anal_function_count_refs (fcn, R_ANAL_REF_TYPE_CALL), 0, "no block holds the call");

	RAnalBlock *bb = r_anal_create_block (anal, 0x1000, 5);
	mu_assert_notnull (bb, "create block");
	bb->ninstr = 1;
	r_anal_function_add_block (fcn, bb);
	r_anal_xrefs_setf (anal, fcn, 0x1000, 0x2000, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (r_anal_function_count_refs (fcn, R_ANAL_REF_TYPE_CALL), 1, "the added block holds the call");

	r_unref (bb);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_count_refs_follows_block_changes(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *f = r_anal_create_function (anal, "f", 0x1000, 0, NULL);
	RAnalFunction *g = r_anal_create_function (anal, "g", 0x800, 0, NULL);
	mu_assert_true (f && g, "create functions");
	// g reaches the block it shares with f from its own entry
	RAnalBlock *entry = r_anal_create_block (anal, 0x800, 0x10);
	entry->jump = 0x1000;
	r_anal_function_add_block (g, entry);
	RAnalBlock *bb = r_anal_create_block (anal, 0x1000, 4);
	bb->ninstr = 1;
	r_anal_function_add_block (f, bb);
	r_anal_function_add_block (g, bb);
	r_anal_xrefs_set (anal, 0x1000, 0x5000, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 0x1002, 0x5000, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 0x2000, 0x5000, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 0x2000, 0x6000, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (r_anal_function_count_refs (f, R_ANAL_REF_TYPE_CALL), 1, "f calls from 0x1000");
	mu_assert_eq (r_anal_function_count_refs (g, R_ANAL_REF_TYPE_CALL), 1, "g calls from 0x1000");

	// the way the function walker appends an instruction
	r_anal_bb_set_offset (bb, bb->ninstr++, 2);
	mu_assert_eq (r_anal_function_count_refs (f, R_ANAL_REF_TYPE_CALL), 2, "f sees the appended call");
	mu_assert_eq (r_anal_function_count_refs (g, R_ANAL_REF_TYPE_CALL), 2, "g sees the appended call");

	r_anal_block_chop_noreturn (bb, 0x1002);
	mu_assert_eq (bb->ninstr, 1, "the chop drops the second instruction");
	mu_assert_eq (r_anal_function_count_refs (f, R_ANAL_REF_TYPE_CALL), 1, "f loses the chopped call");
	mu_assert_eq (r_anal_function_count_refs (g, R_ANAL_REF_TYPE_CALL), 1, "g loses the chopped call");

	mu_assert_true (r_anal_block_relocate (bb, 0x2000, 4), "relocate the block");
	mu_assert_eq (r_anal_function_count_refs (f, R_ANAL_REF_TYPE_CALL), 2, "f counts the calls at the new address");
	mu_assert_eq (r_anal_function_count_refs (g, R_ANAL_REF_TYPE_CALL), 2, "g counts the calls at the new address");

	r_anal_function_remove_block (g, bb);
	mu_assert_eq (r_anal_function_count_refs (g, R_ANAL_REF_TYPE_CALL), 0, "g lost the block");
	mu_assert_eq (r_anal_function_count_refs (f, R_ANAL_REF_TYPE_CALL), 2, "f keeps the block");

	r_unref (bb);
	r_unref (entry);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_count_xrefs_follows_relocate(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "f", 0x1000, 0, NULL);
	mu_assert_notnull (fcn, "create function");
	r_anal_xrefs_set (anal, 0x2000, 0x1000, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 1, "one call to the entry");

	mu_assert_true (r_anal_function_relocate (fcn, 0x3000), "relocate the function");
	mu_assert_eq (r_anal_function_count_xrefs (fcn, R_ANAL_REF_TYPE_ANY), 0, "nothing calls the new entry");

	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_anal_xrefs_count);
	mu_run_test (test_r_anal_purge_clears_xrefs);
	mu_run_test (test_r_anal_xref_del_missing_edge);
	mu_run_test (test_r_anal_xrefs_gen_follows_edge_set);
	mu_run_test (test_r_anal_xrefs_init_keeps_counts_stale);
	mu_run_test (test_r_anal_function_count_refs_sees_added_block);
	mu_run_test (test_r_anal_function_count_refs_follows_block_changes);
	mu_run_test (test_r_anal_function_count_xrefs_follows_relocate);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
