#include <r_anal.h>

#include "minunit.h"
#include "test_sdb.h"

static Sdb *ref_db(void) {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret", "rax", 0);
	sdb_set (db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (db, "cc.sectarian.argn", "stack", 0);
	sdb_set (db, "sectarian", "cc", 0);
	return db;
}

static Sdb *ref_db_self_err(void) {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret", "rax", 0);
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
	// Legacy single-ret + ret2: ret reads as slot 0, ret2 reads as slot 1.
	r_anal_cc_set (anal, "rax legacy(rdi)");
	sdb_set (anal->sdb_cc, "cc.legacy.ret2", "rdx", 0);
	mu_assert_streq (r_anal_cc_ret (anal, "legacy", 0), "rax", "legacy ret -> slot 0");
	mu_assert_streq (r_anal_cc_ret (anal, "legacy", 1), "rdx", "legacy ret2 -> slot 1");
	mu_assert_null (r_anal_cc_ret (anal, "legacy", 2), "past last slot is NULL");

	// Multi-return via the unified r_anal_cc_set parser ("r0,r1,r2 foo(args)").
	r_anal_cc_set (anal, "r0,r1,r2 multi(a0)");
	mu_assert_streq (r_anal_cc_ret (anal, "multi", 0), "r0", "multi: slot 0");
	mu_assert_streq (r_anal_cc_ret (anal, "multi", 1), "r1", "multi: slot 1");
	mu_assert_streq (r_anal_cc_ret (anal, "multi", 2), "r2", "multi: slot 2");
	mu_assert_null (r_anal_cc_ret (anal, "multi", 3), "past last multi slot is NULL");

	// ret.N takes precedence over legacy when both present.
	sdb_set (anal->sdb_cc, "mixed", "cc", 0);
	sdb_set (anal->sdb_cc, "cc.mixed.ret", "rax", 0);
	sdb_set (anal->sdb_cc, "cc.mixed.ret.0", "rcx", 0);
	mu_assert_streq (r_anal_cc_ret (anal, "mixed", 0), "rcx", "ret.0 wins over ret");

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
	mu_run_test (test_r_anal_cc_del);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
