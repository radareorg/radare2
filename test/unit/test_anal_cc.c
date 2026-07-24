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
	const char *vv = r_anal_cc_roleloc (anal, "sectarian", "self");
	mu_assert_null (vv, "get self");
	vv = r_anal_cc_roleloc (anal, "sectarian", "error");
	mu_assert_null (vv, "get error");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_get_self_err(void) {
	RAnal *anal = ref_anal_self_err ();
	char *v = r_anal_cc_get (anal, "sectarian");
	mu_assert_streq (v, "rax rsi.sectarian (rdx, rcx, stack) rdi;", "get cc");
	free (v);
	const char *vv = r_anal_cc_roleloc (anal, "sectarian", "self");
	mu_assert_streq (vv, "rsi", "get self");
	vv = r_anal_cc_roleloc (anal, "sectarian", "error");
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
	mu_assert_streq (r_anal_cc_argloc (anal, "rev", 0, 0, 3), "r2", "revarg first");
	mu_assert_streq (r_anal_cc_argloc (anal, "rev", 1, 0, 3), "r1", "revarg middle");
	mu_assert_streq (r_anal_cc_argloc (anal, "rev", 2, 0, 3), "r0", "revarg last");
	mu_assert_null (r_anal_cc_argloc (anal, "rev", 3, 0, 3), "revarg rejects out-of-range");
	sdb_set (anal->sdb_cc, "cc.rev.argn", "stack", 0);
	mu_assert_streq (r_anal_cc_argloc (anal, "rev", 3, 0, -1), "^", "static stack argn is canonicalized");
	sdb_set (anal->sdb_cc, "cc.rev.argn", "stack_rev", 0);
	mu_assert_streq (r_anal_cc_argloc (anal, "rev", 3, 0, -1), "^-", "static stack_rev argn is canonicalized");

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
	mu_assert_streq (r_anal_cc_argloc (anal, stat, 0, 0, -1), "v6", "static dyncc arg0");
	mu_assert_null (r_anal_cc_argloc (anal, stat, 1, 0, -1), "static dyncc has one arg");
	mu_assert_streq (r_anal_cc_ret (anal, stat, 0), "v0", "static dyncc ret0");
	mu_assert_null (r_anal_cc_ret (anal, stat, 1), "static dyncc has one ret");
	mu_assert_null (r_anal_cc_roleloc (anal, stat, "T"), "static dyncc has no self");
	char *sig = r_anal_cc_get (anal, stat);
	mu_assert_streq (sig, "v0 dyncc:v6:v0 (v6);", "static dyncc signature");
	free (sig);

	const char *inst = "dyncc:v4+3:v0+2!T0";
	mu_assert_true (r_anal_cc_exist (anal, inst), "instance dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, inst), 3, "instance dyncc arg count");
	mu_assert_streq (r_anal_cc_argloc (anal, inst, 0, 0, -1), "v4", "instance dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, inst, 1, 0, -1), "v5", "instance dyncc arg1");
	mu_assert_streq (r_anal_cc_argloc (anal, inst, 2, 0, -1), "v6", "instance dyncc arg2");
	mu_assert_streq (r_anal_cc_ret (anal, inst, 0), "v0", "instance dyncc ret0");
	mu_assert_streq (r_anal_cc_ret (anal, inst, 1), "v1", "instance dyncc ret1");
	mu_assert_null (r_anal_cc_ret (anal, inst, 2), "instance dyncc has two rets");
	mu_assert_streq (r_anal_cc_roleloc (anal, inst, "T"), "v4", "instance dyncc self");
	sig = r_anal_cc_get (anal, inst);
	mu_assert_streq (sig, "v0:v1 v4.dyncc:v4+3:v0+2!T0 (v4, v5, v6);", "instance dyncc signature");
	free (sig);

	const char *shifted = "dyncc:rdi,rsi,rdx:rax!R0!T1!V2!Ex21!Xx20!m2";
	mu_assert_true (r_anal_cc_exist (anal, shifted), "role dyncc exists");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted, "R"), "rdi", "role dyncc sret");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted, "T"), "rsi", "role dyncc shifted self");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted, "V"), "rdx", "role dyncc vtt");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted, "E"), "x21", "role dyncc error");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted, "X"), "x20", "role dyncc context");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted, "m"), "rdx", "role dyncc custom method");
	mu_assert_null (r_anal_cc_roleloc (anal, shifted, "sret"), "dyncc rejects word role lookup");
	sig = r_anal_cc_get (anal, shifted);
	mu_assert_streq (sig, "rax rsi.dyncc:rdi,rsi,rdx:rax!R0!T1!V2!Ex21!Xx20!m2 (rdi, rsi, rdx);", "role dyncc signature");
	free (sig);

	const char *shifted_no_arg0 = "dyncc:_,rsi,rdx:rax!T1";
	mu_assert_true (r_anal_cc_exist (anal, shifted_no_arg0), "explicit self allows instance dyncc without arg0");
	mu_assert_null (r_anal_cc_argloc (anal, shifted_no_arg0, 0, 0, -1), "shifted self dyncc skips arg0");
	mu_assert_streq (r_anal_cc_roleloc (anal, shifted_no_arg0, "T"), "rsi", "shifted self dyncc self");

	const char *sideband_self = "dyncc::rax!Tx20!Ex21";
	mu_assert_true (r_anal_cc_exist (anal, sideband_self), "sideband self dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, sideband_self), 0, "sideband self dyncc has no ABI args");
	mu_assert_streq (r_anal_cc_roleloc (anal, sideband_self, "T"), "x20", "sideband self dyncc self");
	mu_assert_streq (r_anal_cc_roleloc (anal, sideband_self, "E"), "x21", "sideband self dyncc error");

	const char *voidcc = "dyncc:l0:";
	mu_assert_true (r_anal_cc_exist (anal, voidcc), "void dyncc exists");
	mu_assert_null (r_anal_cc_ret (anal, voidcc, 0), "void dyncc has no ret0");
	sig = r_anal_cc_get (anal, voidcc);
	mu_assert_streq (sig, "void dyncc:l0: (l0);", "void dyncc signature");
	free (sig);

	const char *apfx = "dyncc:a0+2:r0";
	mu_assert_true (r_anal_cc_exist (anal, apfx), "a-prefix dyncc exists");
	mu_assert_streq (r_anal_cc_argloc (anal, apfx, 0, 0, -1), "a0", "a-prefix dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, apfx, 1, 0, -1), "a1", "a-prefix dyncc arg1");

	const char *sregs = "dyncc:s0,s1:r0";
	mu_assert_true (r_anal_cc_exist (anal, sregs), "s-register dyncc exists");
	mu_assert_streq (r_anal_cc_argloc (anal, sregs, 0, 0, -1), "s0", "s-register dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, sregs, 1, 0, -1), "s1", "s-register dyncc arg1");

	r_anal_cc_set (anal, "rax rev(r0, r1, r2)");
	sdb_set (anal->sdb_cc, "cc.rev.revarg", "1", 0);
	mu_assert_streq (r_anal_cc_argloc (anal, "rev", 0, 0, 3), "r2", "revarg arg0");
	mu_assert_null (r_anal_cc_argloc (anal, "rev", 3, 0, 3), "revarg rejects past last arg");
	const char *refrev = "dyncc:&rev:&rev";
	mu_assert_streq (r_anal_cc_argloc (anal, refrev, 0, 0, 3), "r2", "referenced dyncc keeps revarg count");

	const char *rev = "dyncc:v1-2:r0";
	mu_assert_true (r_anal_cc_exist (anal, rev), "reverse dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, rev), 2, "reverse dyncc arg count");
	mu_assert_streq (r_anal_cc_argloc (anal, rev, 0, 0, -1), "v1", "reverse dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, rev, 1, 0, -1), "v0", "reverse dyncc arg1");

	const char *mixed = "dyncc:a0+4,^:r0";
	mu_assert_true (r_anal_cc_exist (anal, mixed), "mixed dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, mixed), 4, "mixed dyncc fixed arg count");
	mu_assert_streq (r_anal_cc_argloc (anal, mixed, 0, 0, -1), "a0", "mixed dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, mixed, 3, 0, -1), "a3", "mixed dyncc arg3");
	mu_assert_streq (r_anal_cc_argloc (anal, mixed, 4, 0, -1), "^", "mixed dyncc call-frame tail");
	sig = r_anal_cc_get (anal, mixed);
	mu_assert_streq (sig, "r0 dyncc:a0+4,^:r0 (a0, a1, a2, a3, ^);", "mixed dyncc signature");
	free (sig);

	const char *revstack = "dyncc:a3-4,^-:r0";
	mu_assert_true (r_anal_cc_exist (anal, revstack), "reverse call-frame dyncc exists");
	mu_assert_streq (r_anal_cc_argloc (anal, revstack, 0, 0, -1), "a3", "reverse call-frame dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, revstack, 3, 0, -1), "a0", "reverse call-frame dyncc arg3");
	mu_assert_streq (r_anal_cc_argloc (anal, revstack, 4, 0, -1), "^-", "reverse call-frame dyncc tail");

	const char *expl = "dyncc:ecx,edx,^:eax";
	mu_assert_true (r_anal_cc_exist (anal, expl), "explicit-list dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, expl), 2, "explicit-list fixed arg count");
	mu_assert_streq (r_anal_cc_argloc (anal, expl, 0, 0, -1), "ecx", "explicit-list arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, expl, 1, 0, -1), "edx", "explicit-list arg1");
	mu_assert_streq (r_anal_cc_argloc (anal, expl, 2, 0, -1), "^", "explicit-list call-frame tail");
	mu_assert_streq (r_anal_cc_ret (anal, expl, 0), "eax", "explicit-list ret0");

	const char *homes = "dyncc:a0+4'^0+4,^:r0";
	mu_assert_true (r_anal_cc_exist (anal, homes), "multi-home dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, homes), 4, "multi-home fixed arg count");
	mu_assert_streq (r_anal_cc_argloc (anal, homes, 0, 0, -1), "a0", "multi-home arg0 primary");
	mu_assert_streq (r_anal_cc_argloc (anal, homes, 0, 1, -1), "^0", "multi-home arg0 memory");
	mu_assert_streq (r_anal_cc_argloc (anal, homes, 4, 0, -1), "^", "multi-home tail");

	const char *popcc = "dyncc:ecx,^:eax!p8";
	mu_assert_true (r_anal_cc_exist (anal, popcc), "stack-pop dyncc exists");
	mu_assert_true (r_anal_cc_exist (anal, "dyncc:ecx:eax!p?"), "unknown stack-pop dyncc exists");
	mu_assert_true (r_anal_cc_exist (anal, "dyncc:ecx:eax!p0"), "caller stack-pop dyncc exists");
	const char *regsets = "dyncc:x0+2,^:x0!p8!C(x0,x1,x2)!P(x15,x21,x26,x27,x28)";
	mu_assert_true (r_anal_cc_exist (anal, regsets), "regset dyncc exists");
	mu_assert_true (r_anal_cc_argclob (anal, regsets, 0, regsets), "dyncc clobbers arg0");
	mu_assert_true (r_anal_cc_argclob (anal, regsets, 1, regsets), "dyncc clobbers arg1");
	const char *presonly = "dyncc:x15,x21,x22:x0!P(x15,x21)";
	mu_assert_false (r_anal_cc_argclob (anal, presonly, 0, presonly), "dyncc preserves arg0");
	mu_assert_false (r_anal_cc_argclob (anal, presonly, 1, presonly), "dyncc preserves arg1");
	mu_assert_true (r_anal_cc_argclob (anal, presonly, 2, presonly), "dyncc clobbers unpreserved arg");
	sdb_set (anal->sdb_cc, "cc.sectarian.pop", "12", 0);
	sdb_set (anal->sdb_cc, "cc.sectarian.clobber", "(rdx,rcx)", 0);
	sdb_set (anal->sdb_cc, "cc.sectarian.preserve", "(rsi,rdi)", 0);
	sdb_set (anal->sdb_cc, "cc.sectarian.sret", "rsi", 0);
	mu_assert_true (r_anal_cc_argclob (anal, "sectarian", 0, "sectarian"), "static cc clobbers arg0");
	mu_assert_true (r_anal_cc_argclob (anal, "sectarian", 1, "sectarian"), "static cc clobbers arg1");
	mu_assert_streq (r_anal_cc_roleloc (anal, "sectarian", "sret"), "rsi", "static cc role");
	sdb_set (anal->sdb_cc, "pieces", "cc", 0);
	sdb_set (anal->sdb_cc, "cc.pieces.ret0", "rax", 0);
	sdb_set (anal->sdb_cc, "cc.pieces.arg0", "{0:rdx.4,4:rcx.4}", 0);
	sdb_set (anal->sdb_cc, "cc.pieces.clobber", "(rcx)", 0);
	mu_assert_streq (r_anal_cc_location_first (anal, "{0:rdx.4,4:rcx.4}"), "rdx", "grouped location first register");
	mu_assert_true (r_anal_cc_argclob (anal, "pieces", 0, "pieces"), "static grouped arg clobbers any piece");
	sdb_set (anal->sdb_cc, "cc.pieces.preserve", "(rdx,rcx)", 0);
	mu_assert_false (r_anal_cc_argclob (anal, "pieces", 0, "pieces"), "static grouped arg preserves every piece");

	const char *refcc = "dyncc:&sectarian:&sectarian";
	mu_assert_true (r_anal_cc_exist (anal, refcc), "referenced dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, refcc), 2, "referenced dyncc fixed arg count");
	mu_assert_streq (r_anal_cc_argloc (anal, refcc, 0, 0, -1), "rdx", "referenced dyncc arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, refcc, 1, 0, -1), "rcx", "referenced dyncc arg1");
	mu_assert_streq (r_anal_cc_argloc (anal, refcc, 2, 0, -1), "^", "referenced dyncc argn");
	mu_assert_streq (r_anal_cc_ret (anal, refcc, 0), "rax", "referenced dyncc ret0");
	sig = r_anal_cc_get (anal, refcc);
	mu_assert_streq (sig, "rax dyncc:&sectarian:&sectarian (rdx, rcx, ^);", "referenced dyncc signature");
	free (sig);

	const char *refhomes = "dyncc:rdx'^0,rcx'^1,^:&sectarian";
	mu_assert_true (r_anal_cc_exist (anal, refhomes), "referenced multi-home dyncc exists");
	mu_assert_streq (r_anal_cc_argloc (anal, refhomes, 0, 0, -1), "rdx", "referenced multi-home arg0 primary");
	mu_assert_streq (r_anal_cc_argloc (anal, refhomes, 0, 1, -1), "^0", "referenced multi-home arg0 memory");
	mu_assert_streq (r_anal_cc_argloc (anal, refhomes, 1, 0, -1), "rcx", "referenced multi-home arg1 primary");
	mu_assert_streq (r_anal_cc_argloc (anal, refhomes, 1, 1, -1), "^1", "referenced multi-home arg1 memory");

	const char *refrange = "dyncc:_,rdx,rcx:&sectarian";
	mu_assert_true (r_anal_cc_exist (anal, refrange), "referenced range dyncc exists");
	mu_assert_eq (r_anal_cc_max_arg (anal, refrange), 3, "referenced range dyncc arg count");
	mu_assert_null (r_anal_cc_argloc (anal, refrange, 0, 0, -1), "referenced range skips arg0");
	mu_assert_streq (r_anal_cc_argloc (anal, refrange, 1, 0, -1), "rdx", "referenced range arg1");
	mu_assert_streq (r_anal_cc_argloc (anal, refrange, 2, 0, -1), "rcx", "referenced range arg2");
	mu_assert_null (r_anal_cc_argloc (anal, refrange, 3, 0, -1), "referenced range stops after count");

	const char *refself = "dyncc:_,rdx,rcx:&sectarian!T1";
	mu_assert_true (r_anal_cc_exist (anal, refself), "referenced range dyncc accepts explicit self");
	mu_assert_streq (r_anal_cc_roleloc (anal, refself, "T"), "rdx", "referenced range dyncc explicit self");

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
	mu_assert_null (r_anal_cc_argloc (anal, bad_arg_ref, 0, 0, -1), "per-location dyncc arg reference is not a register");
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

bool test_r_anal_cc_argslot(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 32;
	r_anal_cc_set (anal, "eax flat(stack)");
	RAnalCCArgSlot s;
	// x86-like: no LR alias, so incall skips one return-address word
	mu_assert_true (r_anal_cc_argslot (anal, "flat", 0, -1, false, &s), "flat arg0");
	mu_assert_null (s.reg, "flat arg0 is stack");
	mu_assert_eq (s.off, 0, "flat arg0 at SP");
	mu_assert_eq (s.size, 4, "word slot");
	mu_assert_true (r_anal_cc_argslot (anal, "flat", 2, -1, false, &s), "flat arg2");
	mu_assert_eq (s.off, 8, "flat arg2 at SP+8");
	mu_assert_true (r_anal_cc_argslot (anal, "flat", 2, -1, true, &s), "flat arg2 incall");
	mu_assert_eq (s.off, 12, "incall skips the return address slot");

	r_anal_cc_set (anal, "eax mixed(ecx, edx, stack)");
	mu_assert_true (r_anal_cc_argslot (anal, "mixed", 1, -1, false, &s), "mixed reg arg");
	mu_assert_streq (s.reg, "edx", "mixed arg1 in edx");
	mu_assert_true (r_anal_cc_argslot (anal, "mixed", 3, -1, false, &s), "mixed stack arg");
	mu_assert_eq (s.off, 4, "offsets count from the first stack arg");

	r_anal_cc_set (anal, "eax rt(stack)");
	sdb_set (anal->sdb_cc, "cc.rt.argn", "stack_rev", 0);
	mu_assert_false (r_anal_cc_argslot (anal, "rt", 0, -1, false, &s), "reverse stack needs argc");
	mu_assert_true (r_anal_cc_argslot (anal, "rt", 0, 3, false, &s), "reverse stack with argc");
	mu_assert_eq (s.off, 8, "reverse arg0 sits highest");
	mu_assert_true (r_anal_cc_argslot (anal, "rt", 2, 3, false, &s), "reverse last arg");
	mu_assert_eq (s.off, 0, "reverse last arg at SP");

	// revarg homes the last declared args in registers; they occupy no stack slot
	r_anal_cc_set (anal, "eax dl(eax, stack)");
	sdb_set (anal->sdb_cc, "cc.dl.revarg", "1", 0);
	sdb_set (anal->sdb_cc, "cc.dl.argn", "stack_rev", 0);
	mu_assert_true (r_anal_cc_argslot (anal, "dl", 2, 3, false, &s), "revarg last arg");
	mu_assert_streq (s.reg, "eax", "revarg last arg is register-homed");
	mu_assert_true (r_anal_cc_argslot (anal, "dl", 0, 3, false, &s), "revarg first stack arg");
	mu_assert_eq (s.off, 4, "register-homed args occupy no reverse slot");
	mu_assert_true (r_anal_cc_argslot (anal, "dl", 1, 3, false, &s), "revarg second stack arg");
	mu_assert_eq (s.off, 0, "last pushed stack arg at SP");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_argslot_16bit(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 16;
	r_anal_cc_set (anal, "ax c16(stack)");
	RAnalCCArgSlot s;
	mu_assert_true (r_anal_cc_argslot (anal, "c16", 1, -1, false, &s), "16-bit stack arg");
	mu_assert_eq (s.off, 2, "16-bit pushes make 2-byte slots");
	mu_assert_eq (s.size, 2, "16-bit slot width");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_argslot_shadow(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_cc_set (anal, "rax winish(rcx, rdx, r8, r9, stack)");
	sdb_set (anal->sdb_cc, "cc.winish.shadow", "32", 0);
	RAnalCCArgSlot s;
	mu_assert_true (r_anal_cc_argslot (anal, "winish", 4, -1, false, &s), "first stack arg");
	mu_assert_eq (s.off, 32, "stack args start above the shadow space");
	mu_assert_eq (s.size, 8, "64-bit word slot");
	mu_assert_true (r_anal_cc_argslot (anal, "winish", 4, -1, true, &s), "first stack arg incall");
	mu_assert_eq (s.off, 40, "shadow plus return address slot");
	r_anal_cc_del (anal, "winish");
	mu_assert_null (sdb_const_get (anal->sdb_cc, "cc.winish.shadow", 0), "cc_del removes the shadow key");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_argslot_lr(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 32;
	r_reg_set_profile_string (anal->reg,
		"=PC	pc\n=SP	sp\n=LR	lr\n"
		"gpr	r0	.32	0	0\ngpr	sp	.32	4	0\ngpr	lr	.32	8	0\ngpr	pc	.32	12	0\n");
	r_anal_cc_set (anal, "r0 lrcc(r0, stack)");
	RAnalCCArgSlot s;
	mu_assert_true (r_anal_cc_argslot (anal, "lrcc", 1, -1, true, &s), "lr arch stack arg incall");
	mu_assert_eq (s.off, 0, "no return address slot on link-register archs");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_argslot_homes(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 32;
	RAnalCCArgSlot s;
	// mips o32 dyncc form: a0-a3 primary homes, ^0-^3 secondary stack homes, then the open tail
	const char *cc = "dyncc:a0+4'^0+4,^:v0";
	mu_assert_true (r_anal_cc_argslot (anal, cc, 4, 5, false, &s), "tail after secondary homes");
	mu_assert_eq (s.off, 16, "tail starts past the four home slots");
	mu_assert_true (r_anal_cc_argslot (anal, cc, 0, 5, false, &s), "primary home wins");
	mu_assert_streq (s.reg, "a0", "arg0 resolves to its register home");

	// static o32 models the same home area with the shadow key
	r_anal_cc_set (anal, "v0 so32(a0, a1, a2, a3, stack)");
	sdb_set (anal->sdb_cc, "cc.so32.shadow", "16", 0);
	mu_assert_true (r_anal_cc_argslot (anal, "so32", 4, -1, false, &s), "static o32 first stack arg");
	mu_assert_eq (s.off, 16, "static o32 tail starts past the home area");
	mu_assert_true (r_anal_cc_argslot (anal, "so32", 5, -1, false, &s), "static o32 second stack arg");
	mu_assert_eq (s.off, 20, "later tail args advance by one word");
	r_anal_free (anal);
	mu_end;
}

static bool fake_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = 0x10 + i;
	}
	return true;
}

bool test_r_anal_cc_argval_stack(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 32;
	r_anal_cc_set (anal, "eax scc(stack)");
	r_reg_set_profile_string (anal->reg,
		"=PC	eip\n=SP	esp\n"
		"gpr	esp	.32	0	0\ngpr	eip	.32	4	0\n");
	r_reg_setv (anal->reg, "esp", 0x1000);
	ut64 v = 0;
	mu_assert_false (r_anal_cc_argval (anal, anal->reg, "scc", 0, -1, false, &v), "no io binding fails");
	anal->iob.read_at = fake_read_at;
	mu_assert_true (r_anal_cc_argval (anal, anal->reg, "scc", 0, -1, false, &v), "stack argval reads");
	mu_assert_eq (v, 0x13121110, "little-endian slot decode");
	anal->config->endian = R_SYS_ENDIAN_BIG;
	mu_assert_true (r_anal_cc_argval (anal, anal->reg, "scc", 0, -1, false, &v), "big-endian read");
	mu_assert_eq (v, 0x10111213, "big-endian slot decode");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_argslot_fixed(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 32;
	RAnalCCArgSlot s;
	mu_assert_true (r_anal_cc_argslot (anal, "dyncc:eax,ecx,^0,^2:eax", 2, -1, false, &s), "fixed slot 0");
	mu_assert_eq (s.off, 0, "^0 is call-frame slot zero");
	mu_assert_true (r_anal_cc_argslot (anal, "dyncc:eax,ecx,^0,^2:eax", 3, -1, false, &s), "fixed slot 2");
	mu_assert_eq (s.off, 8, "^2 is two word slots up");
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_argval(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 32;
	r_anal_cc_set (anal, "eax vcc(ecx, stack)");
	r_reg_set_profile_string (anal->reg,
		"=PC	eip\n=SP	esp\n=A0	ecx\n"
		"gpr	ecx	.32	0	0\ngpr	esp	.32	4	0\ngpr	eip	.32	8	0\n");
	r_reg_setv (anal->reg, "ecx", 0x1234);
	ut64 v = 0;
	mu_assert_true (r_anal_cc_argval (anal, anal->reg, "vcc", 0, -1, false, &v), "reg argval");
	mu_assert_eq (v, 0x1234, "reg value read");
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
	mu_run_test (test_r_anal_cc_argslot);
	mu_run_test (test_r_anal_cc_argslot_16bit);
	mu_run_test (test_r_anal_cc_argslot_shadow);
	mu_run_test (test_r_anal_cc_argslot_lr);
	mu_run_test (test_r_anal_cc_argslot_fixed);
	mu_run_test (test_r_anal_cc_argslot_homes);
	mu_run_test (test_r_anal_cc_argval);
	mu_run_test (test_r_anal_cc_argval_stack);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
