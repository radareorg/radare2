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

static int reg_index(RAnal *anal, const char *name) {
	RRegItem *ri = r_reg_get (anal->reg, name, -1);
	int index = ri? ri->index: -1;
	r_unref (ri);
	return index;
}

static RAnalFcnRegArg *find_register_param(RAnalFcnContext *ctx, const char *reg) {
	RListIter *iter;
	RAnalFcnRegArg *arg;

	r_list_foreach (ctx->reg_args, iter, arg) {
		if (arg && arg->reg && !strcmp (arg->reg, reg)) {
			return arg;
		}
	}
	return NULL;
}

static RAnalFcnSlot *find_stack_slot(RAnalFcnContext *ctx, const char *name) {
	RListIter *iter;
	RAnalFcnSlot *slot;

	r_list_foreach (ctx->slots, iter, slot) {
		if (slot && slot->name && !strcmp (slot->name, name)) {
			return slot;
		}
	}
	return NULL;
}

typedef struct {
	int count;
	ut64 block_addr;
	ut64 switch_addr;
	ut64 default_addr;
	ut64 first_case_addr;
	ut64 first_case_value;
} SwitchForeachCtx;

static bool count_switches_cb(RAnalFunction *fcn, RAnalBlock *block, RAnalSwitchOp *op, void *user) {
	SwitchForeachCtx *ctx = user;
	mu_assert_notnull (fcn, "switch callback function");
	mu_assert_notnull (block, "switch callback block");
	mu_assert_notnull (op, "switch callback switch");
	ctx->count++;
	ctx->block_addr = block->addr;
	ctx->switch_addr = op->addr;
	ctx->default_addr = op->def_val;
	RAnalCaseOp *caseop = r_list_first (op->cases);
	mu_assert_notnull (caseop, "switch callback first case");
	ctx->first_case_addr = caseop->jump;
	ctx->first_case_value = caseop->value;
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

bool test_r_anal_function_get_signature(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_true (r_anal_cc_set (anal, "void amd64 (rdi, rsi, rdx, rcx, r8, r9, stack)"),
		"must seed amd64 calling convention");
	RAnalFunction *f = r_anal_create_function (anal, "sigread", 0x2000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for typed cache test");
	bool ok = r_anal_str_to_fcn (anal, f, "int sigread (int arg0, char *arg1);");
	mu_assert_true (ok, "valid signature must apply before cache refresh");

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "typed function name");
	char *typed_cc = r_str_newf ("func.%s.cc=amd64\n", typed_name);
	mu_assert_notnull (typed_cc, "persisted callconv key");
	r_anal_save_parsed_type (anal, typed_cc);

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature must be readable");
	mu_assert_streq (f->name, "sigread", "typed function name");
	mu_assert_streq (signature->ret_type, "int", "typed return type");
	mu_assert_streq (signature->callconv, "amd64", "typed callconv");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "typed param count");
	RAnalFunctionParam *arg0 = r_list_get_n (signature->params, 0);
	RAnalFunctionParam *arg1 = r_list_get_n (signature->params, 1);
	mu_assert_notnull (arg0, "first typed param");
	mu_assert_notnull (arg1, "second typed param");
	mu_assert_streq (arg0->type, "int", "first typed param type");
	mu_assert_streq (arg1->type, "char *", "second typed param type");
	mu_assert_notnull (signature->signature, "typed signature string");

	free (typed_cc);
	free (typed_name);
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_set_signature_uses_canonical_type_name(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal, "int scanf (const char *fmt);", NULL);
	mu_assert_true (ok, "seed canonical scanf signature");

	RAnalFunction *f = r_anal_create_function (anal, "sym.imp.__isoc99_scanf", 0x3000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for typed apply test");
	RAnalFunction *alias = r_anal_create_function (anal, "scanf", 0x3001, 0, NULL);
	mu_assert_notnull (alias, "Couldn't create alias function for typed apply test");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (alias);
	mu_assert_notnull (signature, "alias typed signature must warm");
	r_anal_function_signature_free (signature);

	RAnalFunctionParam params_data[] = {
		{ .name = "format", .type = "const char *" },
		{ .name = "value", .type = "int *" },
	};
	RList *params = r_list_new ();
	mu_assert_notnull (params, "Couldn't create typed apply param list");
	r_list_append (params, &params_data[0]);
	r_list_append (params, &params_data[1]);

	RAnalFunctionSignature input = {
		.ret_type = "int",
		.callconv = "amd64",
		.params = params,
		.noreturn = false,
	};
	ok = r_anal_function_set_signature (anal, f, &input);
	mu_assert_true (ok, "typed signature apply must succeed");
	r_list_free (params);

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "canonical typed name");
	mu_assert_streq (typed_name, "scanf", "apply must reuse canonical type name");
	mu_assert_eq (r_type_func_args_count (anal->sdb_types, typed_name), 2, "typed apply param count");
	mu_assert_null (sdb_const_get (anal->sdb_types, f->name, 0), "apply must not create duplicate import-scoped signature");

	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature read");
	mu_assert_streq (signature->ret_type, "int", "typed apply return type");
	mu_assert_streq (signature->callconv, "amd64", "typed apply callconv");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "typed apply context param count");
	RAnalFunctionParam *arg0 = r_list_get_n (signature->params, 0);
	RAnalFunctionParam *arg1 = r_list_get_n (signature->params, 1);
	mu_assert_notnull (arg0, "first typed param");
	mu_assert_notnull (arg1, "second typed param");
	mu_assert_streq (arg0->name, "format", "first typed param name");
	mu_assert_streq (arg0->type, "const char *", "first typed param type");
	mu_assert_streq (arg1->name, "value", "second typed param name");
	mu_assert_streq (arg1->type, "int *", "second typed param type");
	mu_assert_streq (signature->signature, "int scanf (const char *format, int *value);", "canonical signature string");
	r_anal_function_signature_free (signature);
	mu_assert_streq (f->callconv, "amd64", "typed apply must sync live callconv");

	input.ret_type = "void";
	input.callconv = "cdecl";
	input.params = NULL;
	input.noreturn = true;
	ok = r_anal_function_set_signature (anal, f, &input);
	mu_assert_true (ok, "typed signature overwrite must succeed");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed overwrite signature read");
	mu_assert_streq (signature->ret_type, "void", "typed overwrite return type");
	mu_assert_streq (signature->callconv, "cdecl", "typed overwrite callconv");
	mu_assert_true (f->is_noreturn, "typed overwrite noreturn");
	mu_assert_eq ((int)r_list_length (signature->params), 0, "typed overwrite clears params");
	r_anal_function_signature_free (signature);

	mu_assert_eq (r_type_func_args_count (anal->sdb_types, typed_name), 0, "typed overwrite argc");
	signature = r_anal_function_get_signature (alias);
	mu_assert_notnull (signature, "alias signature must refresh after overwrite");
	mu_assert_streq (signature->ret_type, "void", "alias return type must refresh after overwrite");
	mu_assert_streq (signature->callconv, "cdecl", "alias callconv must refresh after overwrite");
	mu_assert_eq ((int)r_list_length (signature->params), 0, "alias params must refresh after overwrite");
	r_anal_function_signature_free (signature);
	free (typed_name);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_string_uses_import_flag_name(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	RAnal *anal = core->anal;
	bool ok = r_anal_import_c_decls (anal, "int scanf (const char *fmt);", NULL);
	mu_assert_true (ok, "seed canonical scanf signature");

	RAnalFunction *f = r_anal_create_function (anal, "fcn.00003000", 0x3000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for import flag test");
	mu_assert_notnull (
		r_flag_set_inspace (core->flags, R_FLAGS_FS_IMPORTS, "sym.imp.__isoc99_scanf", f->addr, 0),
		"Couldn't create import flag for function"
	);

	char *sig = r_anal_function_get_signature_string (f);
	mu_assert_notnull (sig, "import flag signature");
	mu_assert_streq (sig, "int scanf (const char *fmt);", "import flag must resolve canonical type name");
	free (sig);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_get_signature_uses_basename_for_dbg_prefixed_function(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal, "char * alloc_and_copy (char *src, size_t len);", NULL);
	mu_assert_true (ok, "seed canonical alloc_and_copy signature");

	RAnalFunction *f = r_anal_create_function (anal, "dbg.alloc_and_copy", 0x3100, 0, NULL);
	mu_assert_notnull (f, "Couldn't create dbg-prefixed function");

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "dbg-prefixed function must resolve canonical basename signature");
	mu_assert_streq (signature->ret_type, "char *", "dbg-prefixed return type");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "dbg-prefixed param count");
	RAnalFunctionParam *arg0 = r_list_get_n (signature->params, 0);
	RAnalFunctionParam *arg1 = r_list_get_n (signature->params, 1);
	mu_assert_notnull (arg0, "first dbg-prefixed param");
	mu_assert_notnull (arg1, "second dbg-prefixed param");
	mu_assert_streq (arg0->name, "src", "first dbg-prefixed param name");
	mu_assert_streq (arg0->type, "char *", "first dbg-prefixed param type");
	mu_assert_streq (arg1->name, "len", "second dbg-prefixed param name");
	mu_assert_streq (arg1->type, "size_t", "second dbg-prefixed param type");
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_string_falls_back_to_vars(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "foo", 0x4000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for var fallback test");
	mu_assert_notnull (
		r_anal_function_set_var (f, 8, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, "arg_ch"),
		"Couldn't add second arg var");
	mu_assert_notnull (
		r_anal_function_set_var (f, 4, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, "arg_8h"),
		"Couldn't add first arg var");

	char *sig = r_anal_function_get_signature_string (f);
	mu_assert_notnull (sig, "var fallback signature");
	mu_assert_streq (sig, "void foo (int32_t arg_8h, int32_t arg_ch);", "signature must fall back to sorted arg vars");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "var fallback signature read");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "var fallback param count");
	r_anal_function_signature_free (signature);
	free (sig);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_string_hides_variadic_placeholder(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "foo.bar", 0x5000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for variadic signature test");

	bool ok = r_anal_str_to_fcn (anal, f, "char foo.bar (int a, ...);");
	mu_assert_true (ok, "variadic signature must parse");

	char *sig = r_anal_function_get_signature_string (f);
	mu_assert_notnull (sig, "variadic signature string");
	mu_assert_streq (sig, "char foo.bar (int a, ...);", "variadic placeholder name must stay hidden");
	free (sig);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_falls_back_to_valid_callconv(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_anal_cc_reset (anal);
	mu_assert_true (r_anal_cc_set (anal, "void amd64 (rdi, rsi, rdx, rcx, r8, r9, stack)"),
		"must seed amd64 calling convention");
	r_anal_set_cc_default (anal, "amd64");

	RAnalFunction *f = r_anal_create_function (anal, "sigcc", 0x6000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for callconv fallback test");
	bool ok = r_anal_str_to_fcn (anal, f, "void sigcc (size_t sz);");
	mu_assert_true (ok, "signature must parse");

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature must be readable");
	mu_assert_streq (signature->callconv, "amd64", "invalid persisted cc must fall back to a valid live cc");
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_context_collect_is_conservative_for_stack_slots(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax ctxcall(rdi, rdx, stack)"), "Couldn't seed test-local calling convention");

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn_ctx", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "Couldn't create function for function-context test");
	fcn->callconv = r_str_constpool_get (&anal->constpool, "ctxcall");

	RAnalFunctionParam params_data[] = {
		{ .name = "first", .type = "int" },
		{ .name = "second", .type = "int" },
		{ .name = "third", .type = "int" },
		{ .name = "fourth", .type = "int" },
	};
	RList *params = r_list_new ();
	mu_assert_notnull (params, "Couldn't create param list for function-context test");
	r_list_append (params, &params_data[0]);
	r_list_append (params, &params_data[1]);
	r_list_append (params, &params_data[2]);
	r_list_append (params, &params_data[3]);
	RAnalFunctionSignature signature = {
		.ret_type = "int",
		.callconv = "ctxcall",
		.params = params,
		.noreturn = false,
	};
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature), "typed signature apply for function-context test");
	r_list_free (params);

	const int rdi = reg_index (anal, "rdi");
	const int rdx = reg_index (anal, "rdx");
	mu_assert ("rdi register index must resolve", rdi >= 0);
	mu_assert ("rdx register index must resolve", rdx >= 0);

	RAnalVar *home_source = r_anal_function_set_var (fcn, rdi, R_ANAL_VAR_KIND_REG, "int", 4, true, "arg1");
	RAnalVar *sparse_reg = r_anal_function_set_var (fcn, rdx, R_ANAL_VAR_KIND_REG, "int", 4, true, "arg3");
	RAnalVar *home_slot = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "int", 4, false, "arg1_home");
	RAnalVar *stack_arg = r_anal_function_set_var (fcn, 0x28, R_ANAL_VAR_KIND_SPV, "int", 4, true, "stack_input");
	RAnalVar *saved_named = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_BPV, "int", 4, false, "saved_rbx");
	RAnalVar *arg_named_local = r_anal_function_set_var (fcn, 0x30, R_ANAL_VAR_KIND_SPV, "int", 4, false, "arg2");
	mu_assert_notnull (home_source, "create register home source");
	mu_assert_notnull (sparse_reg, "create sparse register arg");
	mu_assert_notnull (home_slot, "create home slot");
	mu_assert_notnull (stack_arg, "create stack arg");
	mu_assert_notnull (saved_named, "create saved-named local");
	mu_assert_notnull (arg_named_local, "create arg-named local");
	free (home_source->regname);
	home_source->regname = strdup ("rdi");
	free (sparse_reg->regname);
	sparse_reg->regname = strdup ("rdx");

	r_anal_var_set_access (anal, home_source, "rdi", 0x1010, R_PERM_R, 0);
	r_anal_var_set_access (anal, home_slot, "rbp", 0x1010, R_PERM_W, -8);

	RAnalFcnContext *ctx = r_anal_function_context_collect (anal, fcn);
	mu_assert_notnull (ctx, "collect typed function context");

	RAnalFcnRegArg *rdx_param = find_register_param (ctx, "rdx");
	mu_assert_notnull (rdx_param, "sparse register arg must be collected");

	RAnalFcnSlot *home_ctx = find_stack_slot (ctx, "arg1_home");
	RAnalFcnSlot *stack_arg_ctx = find_stack_slot (ctx, "stack_input");
	RAnalFcnSlot *saved_ctx = find_stack_slot (ctx, "saved_rbx");
	RAnalFcnSlot *arg_named_local_ctx = find_stack_slot (ctx, "arg2");
	mu_assert_notnull (home_ctx, "home slot must be present in function context");
	mu_assert_notnull (stack_arg_ctx, "stack arg slot must be present in function context");
	mu_assert_notnull (saved_ctx, "saved-named slot must be present in function context");
	mu_assert_notnull (arg_named_local_ctx, "arg-named local slot must be present in function context");

	mu_assert_eq (home_ctx->role, R_ANAL_FCN_SLOT_HOME, "register-home stack slot must stay param-home");
	mu_assert_eq (home_ctx->arg_index, 0, "param-home slot must use source register param index");
	mu_assert_streq (home_ctx->arg_name, "first", "param-home slot must inherit canonical signature name");
	mu_assert_streq (home_ctx->home_reg, "rdi", "param-home slot must keep source register");

	mu_assert_eq (stack_arg_ctx->role, R_ANAL_FCN_SLOT_ARG, "stack arg slot must stay stack-arg");
	mu_assert_eq (stack_arg_ctx->arg_index, -1, "stack arg slot must not synthesize param indexes from sparse register args");
	mu_assert_null (stack_arg_ctx->arg_name, "stack arg slot must not synthesize a signature param name without a canonical index");

	mu_assert_eq (saved_ctx->role, R_ANAL_FCN_SLOT_LOCAL, "saved-named local must not be reclassified from its spelling");
	mu_assert_eq (arg_named_local_ctx->role, R_ANAL_FCN_SLOT_LOCAL, "arg-named local must not become a param-home without a proven register home");

	r_anal_function_context_free (ctx);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_switches_foreach(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *fcn = r_anal_create_function (anal, "switchy", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "Couldn't create function for switch iteration test");
	RAnalBlock *switch_bb = r_anal_create_block (anal, 0x1000, 0x10);
	RAnalBlock *fallthrough_bb = r_anal_create_block (anal, 0x1010, 0x10);
	mu_assert_notnull (switch_bb, "Couldn't create switch block");
	mu_assert_notnull (fallthrough_bb, "Couldn't create fallthrough block");
	r_anal_function_add_block (fcn, switch_bb);
	r_anal_function_add_block (fcn, fallthrough_bb);
	r_anal_block_add_switch_case (switch_bb, 0x1008, 0, 0x1020);
	r_anal_block_add_switch_case (switch_bb, 0x1008, 1, 0x1030);
	switch_bb->switch_op->def_val = 0x1040;
	switch_bb->switch_op->amount = 2;
	SwitchForeachCtx ctx = {0};
	mu_assert_true (r_anal_function_switches_foreach (fcn, count_switches_cb, &ctx), "switch iteration must succeed");
	mu_assert_eq (ctx.count, 1, "switch iteration count");
	mu_assert_eq (ctx.block_addr, 0x1000, "switch iteration block addr");
	mu_assert_eq (ctx.switch_addr, 0x1008, "switch iteration switch addr");
	mu_assert_eq (ctx.default_addr, 0x1040, "switch iteration default addr");
	mu_assert_eq (ctx.first_case_addr, 0x1020, "switch iteration first case addr");
	mu_assert_eq (ctx.first_case_value, 0, "switch iteration first case value");
	r_unref (switch_bb);
	r_unref (fallthrough_bb);
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_anal_function_relocate);
	mu_run_test (test_r_anal_function_labels);
	mu_run_test (test_r_anal_str_to_fcn_returns_status);
	mu_run_test (test_r_core_anal_fcn_prefers_exact_start_match);
	mu_run_test (test_r_anal_function_get_signature);
	mu_run_test (test_r_anal_function_set_signature_uses_canonical_type_name);
	mu_run_test (test_r_anal_function_get_signature_string_uses_import_flag_name);
	mu_run_test (test_r_anal_function_get_signature_uses_basename_for_dbg_prefixed_function);
	mu_run_test (test_r_anal_function_get_signature_string_falls_back_to_vars);
	mu_run_test (test_r_anal_function_get_signature_string_hides_variadic_placeholder);
	mu_run_test (test_r_anal_function_get_signature_falls_back_to_valid_callconv);
	mu_run_test (test_r_anal_function_context_collect_is_conservative_for_stack_slots);
	mu_run_test (test_r_anal_function_switches_foreach);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
