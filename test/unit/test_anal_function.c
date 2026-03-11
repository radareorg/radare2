#include <r_anal.h>
#include <r_core.h>
#include "minunit.h"
#include <string.h>

#include "test_anal_block_invars.inl"

bool ht_up_count(void *user, const ut64 k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

bool ht_pp_count(void *user, const void *k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

static bool function_check_invariants(RAnal *anal) {
	if (!block_check_invariants (anal)) {
		return false;
	}

	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, it, fcn) {
		mu_assert_ptreq (ht_up_find (anal->ht_addr_fun, fcn->addr, NULL), fcn, "function in addr ht");
		mu_assert_ptreq (ht_pp_find (anal->ht_name_fun, fcn->name, NULL), fcn, "function in name ht");
	}

	size_t addr_count = 0;
	ht_up_foreach (anal->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq (addr_count, r_list_length (anal->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_pp_foreach (anal->ht_name_fun, ht_pp_count, &name_count);
	mu_assert_eq (name_count, r_list_length (anal->fcns), "function name ht count");

	return true;
}

#define check_invariants function_check_invariants
#define check_leaks block_check_leaks

#define assert_invariants(anal) do { if (!check_invariants (anal)) { return false; } } while (0)
#define assert_leaks(anal) do { if (!check_leaks (anal)) { return false; } } while (0)

bool test_r_anal_function_relocate(void) {
	RAnal *anal = r_anal_new ();
	assert_invariants (anal);

	RAnalFunction *fa = r_anal_create_function (anal, "do_something", 0x1337, 0, NULL);
	assert_invariants (anal);
	RAnalFunction *fb = r_anal_create_function (anal, "do_something_else", 0xdeadbeef, 0, NULL);
	assert_invariants (anal);
	r_anal_create_function (anal, "do_something_different", 0xc0ffee, 0, NULL);
	assert_invariants (anal);

	bool success = r_anal_function_relocate (fa, fb->addr);
	assert_invariants (anal);
	mu_assert_false (success, "failed relocate");
	mu_assert_eq (fa->addr, 0x1337, "failed relocate addr");

	success = r_anal_function_relocate (fa, 0x1234);
	assert_invariants (anal);
	mu_assert_true (success, "successful relocate");
	mu_assert_eq (fa->addr, 0x1234, "successful relocate addr");

	assert_leaks (anal);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_labels(void) {
	RAnal *anal = r_anal_new ();

	RAnalFunction *f = r_anal_create_function (anal, "do_something", 0x1337, 0, NULL);

	bool s = r_anal_function_set_label (f, "smartfriend", 0x1339);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "stray", 0x133c);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "the", 0x1340);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "stray", 0x1234);
	mu_assert_false (s, "set label (existing name)");
	s = r_anal_function_set_label (f, "henlo", 0x133c);
	mu_assert_false (s, "set label (existing addr)");

	ut64 addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label");
	addr = r_anal_function_get_label (f, "stray");
	mu_assert_eq (addr, 0x133c, "get label");
	addr = r_anal_function_get_label (f, "skies");
	mu_assert_eq (addr, UT64_MAX, "get label (unknown)");

	const char *name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at");
	name = r_anal_function_get_label_at (f, 0x133c);
	mu_assert_streq (name, "stray", "get label at");
	name = r_anal_function_get_label_at (f, 0x1234);
	mu_assert_null (name, "get label at (unknown)");

	r_anal_function_delete_label (f, "stray");
	addr = r_anal_function_get_label (f, "stray");
	mu_assert_eq (addr, UT64_MAX, "get label (deleted)");
	name = r_anal_function_get_label_at (f, 0x133c);
	mu_assert_null (name, "get label at (deleted)");
	addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label (unaffected by delete)");
	name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at (unaffected by delete)");

	r_anal_function_delete_label_at (f, 0x1340);
	addr = r_anal_function_get_label (f, "the");
	mu_assert_eq (addr, UT64_MAX, "get label (deleted)");
	name = r_anal_function_get_label_at (f, 0x340);
	mu_assert_null (name, "get label at (deleted)");
	addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label (unaffected by delete)");
	name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at (unaffected by delete)");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_str_to_fcn_returns_status(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "sigtest", 0x1000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for signature test");

	bool ok = r_anal_str_to_fcn (anal, f, "int sigtest (int arg0);");
	mu_assert_true (ok, "valid signature must return success");

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "valid signature must create a type entry");

	const char *ret = r_type_func_ret (anal->sdb_types, typed_name);
	int argc = r_type_func_args_count (anal->sdb_types, typed_name);
	char *arg0 = r_type_func_args_type (anal->sdb_types, typed_name, 0);
	mu_assert_true (ret && (!strcmp (ret, "int") || !strcmp (ret, "int32_t")),
		"valid signature should set integer return type");
	mu_assert_eq (argc, 1, "valid signature should set one argument");
	mu_assert_true (arg0 && (!strcmp (arg0, "int") || !strcmp (arg0, "int32_t")),
		"valid signature should keep first argument type");
	free (arg0);

	ok = r_anal_str_to_fcn (anal, f, "int sigtest (");
	mu_assert_false (ok, "invalid signature must return failure");

	ret = r_type_func_ret (anal->sdb_types, typed_name);
	argc = r_type_func_args_count (anal->sdb_types, typed_name);
	arg0 = r_type_func_args_type (anal->sdb_types, typed_name, 0);
	mu_assert_true (ret && (!strcmp (ret, "int") || !strcmp (ret, "int32_t")),
		"invalid signature must not clobber existing return type");
	mu_assert_eq (argc, 1, "invalid signature must not clobber existing argc");
	mu_assert_true (arg0 && (!strcmp (arg0, "int") || !strcmp (arg0, "int32_t")),
		"invalid signature must not clobber existing argument type");
	free (arg0);
	free (typed_name);
	r_anal_free (anal);
	mu_end;
}

bool test_r_core_anal_fcn_prefers_exact_start_match(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	RAnal *anal = core->anal;
	r_config_set_b (core->config, "anal.esil", false);

	RAnalFunction *outer = r_anal_create_function (anal, "outer", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *target = r_anal_create_function (anal, "target", 0x120, R_ANAL_FCN_TYPE_LOC, NULL);
	mu_assert_notnull (outer, "Couldn't create outer function");
	mu_assert_notnull (target, "Couldn't create target function");

	RAnalBlock *outer_bb = r_anal_create_block (anal, 0x100, 0x30);
	RAnalBlock *target_bb = r_anal_create_block (anal, 0x120, 0x10);
	mu_assert_notnull (outer_bb, "Couldn't create outer block");
	mu_assert_notnull (target_bb, "Couldn't create target block");
	r_anal_function_add_block (outer, outer_bb);
	r_anal_function_add_block (target, target_bb);
	r_unref (outer_bb);
	r_unref (target_bb);

	bool ret = r_core_anal_fcn (core, 0x120, 0x104, R_ANAL_REF_TYPE_CALL, 1);
	mu_assert_false (ret, "Exact-start function should short-circuit analysis");
	mu_assert_eq (r_anal_xrefs_count (anal), 0, "Exact-start match should not synthesize a new xref");

	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_readback_collect(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "sigread", 0x2000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for readback test");
	bool ok = r_anal_str_to_fcn (anal, f, "int sigread (int arg0, char *arg1);");
	mu_assert_true (ok, "valid signature must apply before readback");
	f->callconv = strdup ("amd64");

	RAnalFunctionReadback *readback = r_anal_function_readback_collect (anal, f);
	mu_assert_notnull (readback, "readback must be collected");
	mu_assert_streq (readback->ret_type, "int", "readback return type");
	mu_assert_streq (readback->callconv, "amd64", "readback callconv");
	mu_assert_false (readback->has_opaque_type_markers, "typed signature must not be opaque");
	mu_assert_eq ((int)r_list_length (readback->params), 2, "readback param count");
	RAnalFunctionReadbackParam *arg0 = r_list_get_n (readback->params, 0);
	RAnalFunctionReadbackParam *arg1 = r_list_get_n (readback->params, 1);
	mu_assert_notnull (arg0, "first readback param");
	mu_assert_notnull (arg1, "second readback param");
	mu_assert_streq (arg0->type, "int", "first readback param type");
	mu_assert_streq (arg1->type, "char *", "second readback param type");
	mu_assert_notnull (readback->signature, "readback signature string");

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "typed function name for opaque test");
	char *sdb_ret = r_str_newf ("func.%s.ret", typed_name);
	mu_assert_notnull (sdb_ret, "opaque ret key");
	sdb_set (anal->sdb_types, sdb_ret, "type_0x4010", 0);
	r_anal_function_readback_free (readback);
	readback = r_anal_function_readback_collect (anal, f);
	mu_assert_notnull (readback, "opaque readback must be collected");
	mu_assert_true (readback->has_opaque_type_markers, "opaque placeholder must be detected");

	free (sdb_ret);
	free (typed_name);
	r_anal_function_readback_free (readback);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_apply_signature_overwrites_typed_entries(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "sigapply", 0x3000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for typed apply test");

	RAnalFunctionSignatureParam params[] = {
		{ .name = "argc", .type = "int32_t" },
		{ .name = "argv", .type = "char **" },
	};

	bool ok = r_anal_function_apply_signature (anal, f, "int32_t", params, 2, "amd64", false);
	mu_assert_true (ok, "typed signature apply must succeed");

	RAnalFunctionReadback *readback = r_anal_function_readback_collect (anal, f);
	mu_assert_notnull (readback, "typed signature readback");
	mu_assert_streq (readback->ret_type, "int32_t", "typed apply return type");
	mu_assert_streq (readback->callconv, "amd64", "typed apply callconv");
	mu_assert_eq ((int)r_list_length (readback->params), 2, "typed apply param count");
	RAnalFunctionReadbackParam *arg0 = r_list_get_n (readback->params, 0);
	RAnalFunctionReadbackParam *arg1 = r_list_get_n (readback->params, 1);
	mu_assert_notnull (arg0, "first typed param");
	mu_assert_notnull (arg1, "second typed param");
	mu_assert_streq (arg0->name, "argc", "first typed param name");
	mu_assert_streq (arg0->type, "int32_t", "first typed param type");
	mu_assert_streq (arg1->name, "argv", "second typed param name");
	mu_assert_streq (arg1->type, "char **", "second typed param type");
	r_anal_function_readback_free (readback);

	ok = r_anal_function_apply_signature (anal, f, "void", NULL, 0, "cdecl", true);
	mu_assert_true (ok, "typed signature overwrite must succeed");
	readback = r_anal_function_readback_collect (anal, f);
	mu_assert_notnull (readback, "typed overwrite readback");
	mu_assert_streq (readback->ret_type, "void", "typed overwrite return type");
	mu_assert_streq (readback->callconv, "cdecl", "typed overwrite callconv");
	mu_assert_true (readback->noreturn, "typed overwrite noreturn");
	mu_assert_eq ((int)r_list_length (readback->params), 0, "typed overwrite clears params");

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "typed name must exist after overwrite");
	mu_assert_eq (r_type_func_args_count (anal->sdb_types, typed_name), 0, "typed overwrite argc");
	free (typed_name);

	r_anal_function_readback_free (readback);
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_anal_function_relocate);
	mu_run_test (test_r_anal_function_labels);
	mu_run_test (test_r_anal_str_to_fcn_returns_status);
	mu_run_test (test_r_core_anal_fcn_prefers_exact_start_match);
	mu_run_test (test_r_anal_function_readback_collect);
	mu_run_test (test_r_anal_function_apply_signature_overwrites_typed_entries);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
