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

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_dyncc(void) {
	RAnal *anal = r_anal_new ();
	r_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");

	mu_assert_true (r_anal_cc_exist (anal, "dyncc"), "dyncc marker exists");

	const char *stat = "dyncc:v6:v0";
	mu_assert_true (r_anal_cc_exist (anal, stat), "static dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, stat), 1, "static dyncc arg count");
	mu_assert_streq (r_anal_cc_arg (anal, stat, 0, -1), "v6", "static dyncc arg0");
	mu_assert_null (r_anal_cc_arg (anal, stat, 1, -1), "static dyncc has one arg");
	mu_assert_streq (r_anal_cc_ret (anal, stat, 0), "v0", "static dyncc ret0");
	mu_assert_null (r_anal_cc_ret (anal, stat, 1), "static dyncc has one ret");
	mu_assert_null (r_anal_cc_self (anal, stat), "static dyncc has no self");
	char *sig = r_anal_cc_get (anal, stat);
	mu_assert_streq (sig, "v0 dyncc:v6:v0 (v6);", "static dyncc signature");
	free (sig);

	const char *inst = "dyncc:v4+3:v0+2!T0";
	mu_assert_true (r_anal_cc_exist (anal, inst), "instance dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, inst), 3, "instance dyncc arg count");
	mu_assert_streq (r_anal_cc_arg (anal, inst, 0, -1), "v4", "instance dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, inst, 1, -1), "v5", "instance dyncc arg1");
	mu_assert_streq (r_anal_cc_arg (anal, inst, 2, -1), "v6", "instance dyncc arg2");
	mu_assert_streq (r_anal_cc_ret (anal, inst, 0), "v0", "instance dyncc ret0");
	mu_assert_streq (r_anal_cc_ret (anal, inst, 1), "v1", "instance dyncc ret1");
	mu_assert_null (r_anal_cc_ret (anal, inst, 2), "instance dyncc has two rets");
	mu_assert_streq (r_anal_cc_self (anal, inst), "v4", "instance dyncc self");
	sig = r_anal_cc_get (anal, inst);
	mu_assert_streq (sig, "v0:v1 v4.dyncc:v4+3:v0+2!T0 (v4, v5, v6);", "instance dyncc signature");
	free (sig);

	const char *shifted = "dyncc:rdi,rsi,rdx:rax!R0!T1!V2!Ex21!Xx20!m2";
	mu_assert_true (r_anal_cc_exist (anal, shifted), "role dyncc exists");
	mu_assert_streq (r_anal_cc_role (anal, shifted, "R"), "rdi", "role dyncc sret");
	mu_assert_streq (r_anal_cc_self (anal, shifted), "rsi", "role dyncc shifted self");
	mu_assert_streq (r_anal_cc_role (anal, shifted, "V"), "rdx", "role dyncc vtt");
	mu_assert_streq (r_anal_cc_error (anal, shifted), "x21", "role dyncc error");
	mu_assert_streq (r_anal_cc_role (anal, shifted, "X"), "x20", "role dyncc context");
	mu_assert_streq (r_anal_cc_role (anal, shifted, "m"), "rdx", "role dyncc custom method");
	mu_assert_null (r_anal_cc_role (anal, shifted, "sret"), "dyncc rejects word role lookup");
	sig = r_anal_cc_get (anal, shifted);
	mu_assert_streq (sig, "rax rsi.dyncc:rdi,rsi,rdx:rax!R0!T1!V2!Ex21!Xx20!m2 (rdi, rsi, rdx);", "role dyncc signature");
	free (sig);

	const char *shifted_no_arg0 = "dyncc:_,rsi,rdx:rax!T1";
	mu_assert_true (r_anal_cc_exist (anal, shifted_no_arg0), "explicit self allows instance dyncc without arg0");
	mu_assert_null (r_anal_cc_arg (anal, shifted_no_arg0, 0, -1), "shifted self dyncc skips arg0");
	mu_assert_streq (r_anal_cc_self (anal, shifted_no_arg0), "rsi", "shifted self dyncc self");

	const char *sideband_self = "dyncc::rax!Tx20!Ex21";
	mu_assert_true (r_anal_cc_exist (anal, sideband_self), "sideband self dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, sideband_self), 0, "sideband self dyncc has no ABI args");
	mu_assert_streq (r_anal_cc_self (anal, sideband_self), "x20", "sideband self dyncc self");
	mu_assert_streq (r_anal_cc_error (anal, sideband_self), "x21", "sideband self dyncc error");

	const char *voidcc = "dyncc:l0:";
	mu_assert_true (r_anal_cc_exist (anal, voidcc), "void dyncc exists");
	mu_assert_null (r_anal_cc_ret (anal, voidcc, 0), "void dyncc has no ret0");
	sig = r_anal_cc_get (anal, voidcc);
	mu_assert_streq (sig, "void dyncc:l0: (l0);", "void dyncc signature");
	free (sig);

	const char *apfx = "dyncc:a0+2:r0";
	mu_assert_true (r_anal_cc_exist (anal, apfx), "a-prefix dyncc exists");
	mu_assert_streq (r_anal_cc_arg (anal, apfx, 0, -1), "a0", "a-prefix dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, apfx, 1, -1), "a1", "a-prefix dyncc arg1");

	const char *sregs = "dyncc:s0,s1:r0";
	mu_assert_true (r_anal_cc_exist (anal, sregs), "s-register dyncc exists");
	mu_assert_streq (r_anal_cc_arg (anal, sregs, 0, -1), "s0", "s-register dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, sregs, 1, -1), "s1", "s-register dyncc arg1");

	r_anal_cc_set (anal, "rax rev(r0, r1, r2)");
	sdb_set (anal->sdb_cc, "cc.rev.revarg", "1", 0);
	mu_assert_streq (r_anal_cc_arg (anal, "rev", 0, 3), "r2", "revarg arg0");
	mu_assert_null (r_anal_cc_arg (anal, "rev", 3, 3), "revarg rejects past last arg");
	const char *refrev = "dyncc:&rev:&rev";
	mu_assert_streq (r_anal_cc_arg (anal, refrev, 0, 3), "r2", "referenced dyncc keeps revarg count");

	const char *rev = "dyncc:v1-2:r0";
	mu_assert_true (r_anal_cc_exist (anal, rev), "reverse dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, rev), 2, "reverse dyncc arg count");
	mu_assert_streq (r_anal_cc_arg (anal, rev, 0, -1), "v1", "reverse dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, rev, 1, -1), "v0", "reverse dyncc arg1");

	const char *mixed = "dyncc:a0+4,^:r0";
	mu_assert_true (r_anal_cc_exist (anal, mixed), "mixed dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, mixed), 4, "mixed dyncc fixed arg count");
	mu_assert_streq (r_anal_cc_arg (anal, mixed, 0, -1), "a0", "mixed dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, mixed, 3, -1), "a3", "mixed dyncc arg3");
	mu_assert_streq (r_anal_cc_arg (anal, mixed, 4, -1), "^", "mixed dyncc call-frame tail");
	sig = r_anal_cc_get (anal, mixed);
	mu_assert_streq (sig, "r0 dyncc:a0+4,^:r0 (a0, a1, a2, a3, ^);", "mixed dyncc signature");
	free (sig);

	const char *revstack = "dyncc:a3-4,^-:r0";
	mu_assert_true (r_anal_cc_exist (anal, revstack), "reverse call-frame dyncc exists");
	mu_assert_streq (r_anal_cc_arg (anal, revstack, 0, -1), "a3", "reverse call-frame dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, revstack, 3, -1), "a0", "reverse call-frame dyncc arg3");
	mu_assert_streq (r_anal_cc_arg (anal, revstack, 4, -1), "^-", "reverse call-frame dyncc tail");

	const char *expl = "dyncc:ecx,edx,^:eax";
	mu_assert_true (r_anal_cc_exist (anal, expl), "explicit-list dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, expl), 2, "explicit-list fixed arg count");
	mu_assert_streq (r_anal_cc_arg (anal, expl, 0, -1), "ecx", "explicit-list arg0");
	mu_assert_streq (r_anal_cc_arg (anal, expl, 1, -1), "edx", "explicit-list arg1");
	mu_assert_streq (r_anal_cc_arg (anal, expl, 2, -1), "^", "explicit-list call-frame tail");
	mu_assert_streq (r_anal_cc_ret (anal, expl, 0), "eax", "explicit-list ret0");

	const char *homes = "dyncc:a0+4'^0+4,^:r0";
	mu_assert_true (r_anal_cc_exist (anal, homes), "multi-home dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, homes), 4, "multi-home fixed arg count");
	mu_assert_streq (r_anal_cc_arg_home (anal, homes, 0, 0, -1), "a0", "multi-home arg0 primary");
	mu_assert_streq (r_anal_cc_arg_home (anal, homes, 0, 1, -1), "^0", "multi-home arg0 memory");
	mu_assert_streq (r_anal_cc_arg_home (anal, homes, 4, 0, -1), "^", "multi-home tail");

	mu_assert_true (r_anal_cc_location_uses (anal, "eax", "eax"), "plain location contains itself");
	mu_assert_false (r_anal_cc_location_uses (anal, "eax", "edx"), "plain location excludes other registers");
	mu_assert_streq (r_anal_cc_location_first (anal, "eax"), "eax", "plain first location");
	mu_assert_true (r_anal_cc_location_uses (anal, "{edx:eax}", "eax"), "group contains eax");
	mu_assert_true (r_anal_cc_location_in_regset (anal, "{edx:eax}", "(ecx,eax)", false), "group regset any match");
	mu_assert_true (r_anal_cc_location_in_regset (anal, "{edx:eax}", "(edx,eax)", true), "group regset all match");
	mu_assert_false (r_anal_cc_location_in_regset (anal, "{edx:eax}", "(eax)", true), "group regset all miss");
	mu_assert_streq (r_anal_cc_location_first (anal, "{edx:eax}"), "edx", "group first piece");
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	mu_assert_true (r_anal_cc_location_pieces (anal, "{0:rdi,8:rsi.4}", &pieces), "scattered pieces parse");
	mu_assert_eq (RVecAnalCCPiece_length (&pieces), 2, "scattered piece count");
	RAnalCCPiece *piece = RVecAnalCCPiece_at (&pieces, 1);
	mu_assert_eq (piece->off, 8, "scattered piece offset");
	mu_assert_eq (piece->size, 4, "scattered piece size");
	mu_assert_streq (piece->loc, "rsi", "scattered piece loc");
	RVecAnalCCPiece_fini (&pieces);

	const char *popcc = "dyncc:ecx,^:eax!p8";
	mu_assert_true (r_anal_cc_exist (anal, popcc), "stack-pop dyncc exists");
	mu_assert_eq (r_anal_cc_stack_pop (anal, popcc), 8, "stack-pop dyncc purges eight bytes");
	mu_assert_eq (r_anal_cc_stack_pop (anal, "dyncc:ecx:eax!p?"), R_ANAL_CC_STACK_POP_UNKNOWN, "callee dyncc has unknown pop");
	mu_assert_eq (r_anal_cc_stack_pop (anal, "dyncc:ecx:eax!p0"), 0, "caller dyncc has no fixed pop");
	const char *regsets = "dyncc:x0+2,^:x0!p8!C(x0,x1,x2)!P(x15,x21,x26,x27,x28)";
	mu_assert_true (r_anal_cc_exist (anal, regsets), "regset dyncc exists");
	mu_assert_eq (r_anal_cc_stack_pop (anal, regsets), 8, "regset dyncc stack-pop");
	mu_assert_streq (r_anal_cc_clobbers (anal, regsets), "(x0,x1,x2)", "dyncc clobbers");
	mu_assert_streq (r_anal_cc_preserves (anal, regsets), "(x15,x21,x26,x27,x28)", "dyncc preserves");
	mu_assert_false (r_anal_cc_regset_contains ("(x0,x1,x2)", "x3"), "regset negative match");
	sdb_set (anal->sdb_cc, "cc.sectarian.pop", "12", 0);
	sdb_set (anal->sdb_cc, "cc.sectarian.clobber", "(rdx,rcx)", 0);
	sdb_set (anal->sdb_cc, "cc.sectarian.preserve", "(rsi,rdi)", 0);
	sdb_set (anal->sdb_cc, "cc.sectarian.sret", "rsi", 0);
	mu_assert_eq (r_anal_cc_stack_pop (anal, "sectarian"), 12, "static cc stack-pop");
	mu_assert_streq (r_anal_cc_clobbers (anal, "sectarian"), "(rdx,rcx)", "static cc clobbers");
	mu_assert_streq (r_anal_cc_preserves (anal, "sectarian"), "(rsi,rdi)", "static cc preserves");
	mu_assert_streq (r_anal_cc_role (anal, "sectarian", "sret"), "rsi", "static cc role");

	const char *refcc = "dyncc:&sectarian:&sectarian";
	mu_assert_true (r_anal_cc_exist (anal, refcc), "referenced dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, refcc), 2, "referenced dyncc fixed arg count");
	mu_assert_streq (r_anal_cc_arg (anal, refcc, 0, -1), "rdx", "referenced dyncc arg0");
	mu_assert_streq (r_anal_cc_arg (anal, refcc, 1, -1), "rcx", "referenced dyncc arg1");
	mu_assert_streq (r_anal_cc_arg (anal, refcc, 2, -1), "^", "referenced dyncc argn");
	mu_assert_streq (r_anal_cc_ret (anal, refcc, 0), "rax", "referenced dyncc ret0");
	sig = r_anal_cc_get (anal, refcc);
	mu_assert_streq (sig, "rax dyncc:&sectarian:&sectarian (rdx, rcx, ^);", "referenced dyncc signature");
	free (sig);

	const char *refhomes = "dyncc:rdx'^0,rcx'^1,^:&sectarian";
	mu_assert_true (r_anal_cc_exist (anal, refhomes), "referenced multi-home dyncc exists");
	mu_assert_streq (r_anal_cc_arg_home (anal, refhomes, 0, 0, -1), "rdx", "referenced multi-home arg0 primary");
	mu_assert_streq (r_anal_cc_arg_home (anal, refhomes, 0, 1, -1), "^0", "referenced multi-home arg0 memory");
	mu_assert_streq (r_anal_cc_arg_home (anal, refhomes, 1, 0, -1), "rcx", "referenced multi-home arg1 primary");
	mu_assert_streq (r_anal_cc_arg_home (anal, refhomes, 1, 1, -1), "^1", "referenced multi-home arg1 memory");

	const char *refrange = "dyncc:_,rdx,rcx:&sectarian";
	mu_assert_true (r_anal_cc_exist (anal, refrange), "referenced range dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, refrange), 3, "referenced range dyncc arg count");
	mu_assert_null (r_anal_cc_arg (anal, refrange, 0, -1), "referenced range skips arg0");
	mu_assert_streq (r_anal_cc_arg (anal, refrange, 1, -1), "rdx", "referenced range arg1");
	mu_assert_streq (r_anal_cc_arg (anal, refrange, 2, -1), "rcx", "referenced range arg2");
	mu_assert_null (r_anal_cc_arg (anal, refrange, 3, -1), "referenced range stops after count");

	const char *refself = "dyncc:_,rdx,rcx:&sectarian!T1";
	mu_assert_true (r_anal_cc_exist (anal, refself), "referenced range dyncc accepts explicit self");
	mu_assert_streq (r_anal_cc_self (anal, refself), "rdx", "referenced range dyncc explicit self");

	mu_assert_true (r_anal_cc_exist (anal, "dyncc:v0+1:v0"), "one-item dyncc range");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:v0+0:v0"), "invalid zero dyncc range");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:v0-2:v0"), "invalid reverse dyncc underflow");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:v0:v+1"), "invalid dyncc ret range");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:a0,stack:r0"), "invalid dyncc stack word");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:v0,,v1:r0"), "invalid empty dyncc arg");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:a0,!:r0"), "invalid dyncc map");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:{edx:eax}:v0"), "group maps one dyncc arg");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:ecx:eax!px"), "invalid dyncc stack-pop");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:ecx:eax!P"), "invalid dyncc empty preserve");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:ecx:eax!R1"), "invalid dyncc missing role arg");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:ecx:eax!M0"), "invalid dyncc unknown role");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:&missing:rax"), "missing dyncc arg reference");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:rdi:&missing"), "missing dyncc ret reference");
	const char *bad_arg_ref = "dyncc:&missing,a0:rax";
	mu_assert_false (r_anal_cc_exist (anal, bad_arg_ref), "invalid per-location dyncc arg reference");
	mu_assert_null (r_anal_cc_arg (anal, bad_arg_ref, 0, -1), "per-location dyncc arg reference is not a register");
	const char *bad_ret_ref = "dyncc:a0:&missing,rax";
	mu_assert_false (r_anal_cc_exist (anal, bad_ret_ref), "invalid per-location dyncc ret reference");
	mu_assert_null (r_anal_cc_ret (anal, bad_ret_ref, 0), "per-location dyncc ret reference is not a register");
	mu_assert_false (r_anal_cc_exist (anal, "dyncc:a0:rax!T&missing"), "invalid per-role dyncc reference");

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
	mu_run_test (test_r_anal_cc_dyncc);
	mu_run_test (test_r_anal_cc_del);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
