#include <r_anal.h>

#include "minunit.h"
#include "test_sdb.h"

static Sdb *ref_db(void) {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret0", "rax", 0);
	sdb_set (db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (db, "cc.sectarian.argn", "stack", 0);
	sdb_set (db, "sectarian", "cc", 0);
	return db;
}

static Sdb *ref_db_self_err(void) {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret0", "rax", 0);
	sdb_set (db, "cc.sectarian.self", "rsi", 0);
	sdb_set (db, "cc.sectarian.error", "rdi", 0);
	sdb_set (db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (db, "cc.sectarian.argn", "stack", 0);
	sdb_set (db, "sectarian", "cc", 0);
	return db;
}

static RAnal *ref_anal(void) {
	RAnal *anal = r_anal_new ();
	r_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");
	return anal;
}

static RAnal *ref_anal_self_err(void) {
	RAnal *anal = r_anal_new ();
	r_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");
	r_anal_cc_set_self (anal, "sectarian", "rsi");
	r_anal_cc_set_error (anal, "sectarian", "rdi");
	return anal;
}

bool test_r_anal_cc_set(void) {
	RAnal *anal = ref_anal ();

	Sdb *ref = ref_db ();
	assert_sdb_eq (anal->sdb_cc, ref, "set cc");
	sdb_free (ref);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_set_self_err(void) {
	RAnal *anal = ref_anal_self_err ();

	Sdb *ref = ref_db_self_err ();
	assert_sdb_eq (anal->sdb_cc, ref, "set cc");
	sdb_free (ref);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_get(void) {
	RAnal *anal = ref_anal ();
	char *v = r_anal_cc_get (anal, "sectarian");
	mu_assert_streq (v, "rax sectarian (rdx, rcx, stack);", "get cc");
	free (v);
	const char *vv = r_anal_cc_self (anal, "sectarian");
	mu_assert_null (vv, "get self");
	vv = r_anal_cc_error (anal, "sectarian");
	mu_assert_null (vv, "get error");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_get_self_err(void) {
	RAnal *anal = ref_anal_self_err ();
	char *v = r_anal_cc_get (anal, "sectarian");
	mu_assert_streq (v, "rax rsi.sectarian (rdx, rcx, stack) rdi;", "get cc");
	free (v);
	const char *vv = r_anal_cc_self (anal, "sectarian");
	mu_assert_streq (vv, "rsi", "get self");
	vv = r_anal_cc_error (anal, "sectarian");
	mu_assert_streq (vv, "rdi", "get error");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_multiret(void) {
	RAnal *anal = r_anal_new ();
	r_anal_cc_set (anal, "r0,r1,r2 multi(a0)");
	mu_assert_eq (sdb_num_get (anal->sdb_cc, "cc.multi.retn", 0), 3, "multi: retn");
	mu_assert_streq (r_anal_cc_ret (anal, "multi", 0), "r0", "multi: slot 0");
	mu_assert_streq (r_anal_cc_ret (anal, "multi", 1), "r1", "multi: slot 1");
	mu_assert_streq (r_anal_cc_ret (anal, "multi", 2), "r2", "multi: slot 2");
	mu_assert_null (r_anal_cc_ret (anal, "multi", 3), "past last multi slot is NULL");

	r_anal_cc_set (anal, "rax single(rdi)");
	mu_assert_streq (r_anal_cc_ret (anal, "single", 0), "rax", "single ret");
	mu_assert_null (r_anal_cc_ret (anal, "single", 1), "single ret has no second slot");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_static_fixes(void) {
	RAnal *anal = r_anal_new ();
	r_anal_cc_set (anal, "rax rev(r0, r1, r2)");
	sdb_set (anal->sdb_cc, "cc.rev.revarg", "1", 0);
	mu_assert_streq (r_anal_cc_arg (anal, "rev", 0, 3), "r2", "revarg first");
	mu_assert_streq (r_anal_cc_arg (anal, "rev", 1, 3), "r1", "revarg middle");
	mu_assert_streq (r_anal_cc_arg (anal, "rev", 2, 3), "r0", "revarg last");
	mu_assert_null (r_anal_cc_arg (anal, "rev", 3, 3), "revarg rejects out-of-range");

	r_anal_cc_set (anal, "rax grow(r0)");
	mu_assert_eq (r_anal_cc_max_arg (anal, "grow"), 1, "initial max args");
	sdb_set (anal->sdb_cc, "cc.grow.arg1", "r1", 0);
	mu_assert_eq (r_anal_cc_max_arg (anal, "grow"), 2, "max args after db update");

	PJ *pj = pj_new ();
	mu_assert_notnull (pj, "pj");
	pj_o (pj);
	r_anal_cc_get_json (anal, pj, "missing");
	pj_end (pj);
	mu_assert_streq (pj_string (pj), "{}", "missing cc json");
	pj_free (pj);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_del(void) {
	RAnal *anal = ref_anal ();
	r_anal_cc_del (anal, "sectarian");
	Sdb *ref = sdb_new0 ();
	assert_sdb_eq (anal->sdb_cc, ref, "deleted");
	sdb_free (ref);
	r_anal_free (anal);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_anal_cc_set);
	mu_run_test (test_r_anal_cc_set_self_err);
	mu_run_test (test_r_anal_cc_get);
	mu_run_test (test_r_anal_cc_get_self_err);
	mu_run_test (test_r_anal_cc_multiret);
	mu_run_test (test_r_anal_cc_static_fixes);
	mu_run_test (test_r_anal_cc_del);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
