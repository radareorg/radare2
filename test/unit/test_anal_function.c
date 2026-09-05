#include <r_anal.h>
#include <r_anal_priv.h>
#include <r_core.h>
#include "minunit.h"
#include <string.h>

#include "../../libr/anal/function_snapshot.h"

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



static RBinAddr snapshot_test_loader_init;


static bool set_function_type_link(RAnal *anal, const char *type, ut64 addr);



static int snapshot_lazy_cc_calls;

static const char *snapshot_lazy_cc(RBin *bin, ut64 addr) {
	(void)bin;
	(void)addr;
	snapshot_lazy_cc_calls++;
	return "cdecl";
}


static bool set_function_type_link(RAnal *anal, const char *type, ut64 addr) {
	RAnalMutation mutation = {
		.kind = R_ANAL_MUTATION_TYPE_LINK,
		.type = type,
		.addr = addr,
	};
	return r_anal_apply_mutations (anal, &mutation, 1, NULL);
}



static bool save_snapshot_demo_struct_type(
	RAnal *anal, size_t fourteenth_offset, size_t fourteenth_count) {
	static const char *names[] = {
		"first", "second", "third", "fourth", "fifth", "sixth", "seventh",
		"eighth", "ninth", "tenth", "eleventh", "twelfth", "thirteenth",
		"fourteenth",
	};
	RAnalBaseType *type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	if (!type) {
		return false;
	}
	type->name = strdup ("DemoStruct");
	type->size = R_ARRAY_SIZE (names) * 32;
	if (!type->name) {
		r_anal_base_type_free (type);
		return false;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		RAnalStructMember member = {
			.name = strdup (names[i]),
			.type = strdup ("int32_t"),
			.offset = i == R_ARRAY_SIZE (names) - 1? fourteenth_offset: i * 4,
			.count = i == R_ARRAY_SIZE (names) - 1? fourteenth_count: 0,
		};
		if (!member.name || !member.type) {
			anal_type_member_fini (&member);
			r_anal_base_type_free (type);
			return false;
		}
		RAnalStructMember *element = RVecAnalTypeMember_emplace_back (
			&type->struct_data.members);
		if (!element) {
			anal_type_member_fini (&member);
			r_anal_base_type_free (type);
			return false;
		}
		*element = member;
	}
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);
	return true;
}

static bool save_snapshot_atomic_type(
	RAnal *anal, const char *name, const char *encoding, ut64 size) {
	RAnalBaseType *type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (!type) {
		return false;
	}
	type->name = strdup (name);
	type->type = strdup (encoding);
	type->size = size;
	if (!type->name || !type->type) {
		r_anal_base_type_free (type);
		return false;
	}
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);
	return true;
}

static bool save_snapshot_typedef_type(RAnal *anal, const char *name, const char *target) {
	RAnalBaseType *type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	if (!type) {
		return false;
	}
	type->name = strdup (name);
	type->type = strdup (target);
	if (!type->name || !type->type) {
		r_anal_base_type_free (type);
		return false;
	}
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);
	return true;
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
	ut64 revision_epoch = r_anal_function_dirty_epoch (fa);

	success = r_anal_function_relocate (fa, 0x1234);
	assert_invariants (anal);
	mu_assert_true (success, "successful relocate");
	mu_assert_eq (fa->addr, 0x1234, "successful relocate addr");
	mu_assert_neq (r_anal_function_dirty_epoch (fa), revision_epoch,
		"relocation bumps the function revision epoch");
	revision_epoch = r_anal_function_dirty_epoch (fa);
	mu_assert_true (r_anal_function_rename (fa, "relocated_function"),
		"rename relocated function");
	mu_assert_neq (r_anal_function_dirty_epoch (fa), revision_epoch,
		"rename bumps the function revision epoch");

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

bool test_r_core_anal_fcn_variadic_marker_requires_unclobbered_al(void) {
	const ut64 addr = 0x1000;
	const ut8 bytes[] = {
		0x0f, 0xb6, 0x07, // movzx eax, byte [rdi]
		0x84, 0xc0, // test al, al
		0xc3, // ret
		0x84, 0xc0, // test al, al
		0x74, 0x01, // je +1
		0xc3, // ret
		0xc3, // ret
	};
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://12",
		R_PERM_RWX, 0, addr), "open variadic marker test map");
	mu_assert_true (r_io_write_at (core->io, addr, bytes, sizeof (bytes)),
		"write variadic marker test bytes");
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	r_config_set_b (core->config, "anal.esil", false);

	mu_assert_true (r_core_anal_fcn (core, addr, UT64_MAX,
		R_ANAL_REF_TYPE_NULL, 1), "analyze clobbered marker function");
	RAnalFunction *clobbered = r_anal_get_function_at (core->anal, addr);
	mu_assert_notnull (clobbered, "analysis creates clobbered marker function");
	mu_assert_false (clobbered->is_variadic,
		"writing eax invalidates the incoming al variadic marker");

	const ut64 preserved_addr = addr + 6;
	mu_assert_true (r_core_anal_fcn (core, preserved_addr, UT64_MAX,
		R_ANAL_REF_TYPE_NULL, 1), "analyze preserved marker function");
	RAnalFunction *preserved = r_anal_get_function_at (core->anal, preserved_addr);
	mu_assert_notnull (preserved, "analysis creates preserved marker function");
	mu_assert_true (preserved->is_variadic,
		"an unclobbered test of al remains a variadic marker");

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

bool test_r_anal_function_get_signature_prefers_exact_type_link(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal,
		"int fallback_signature (int fallback);"
		"char linked_signature (char linked);"
		"void renamed_signature (void);", NULL);
	mu_assert_true (ok, "seed linked and fallback signatures");

	RAnalFunction *f = r_anal_create_function (anal, "fallback_signature", 0x2800, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for exact type link test");
	mu_assert_true (r_type_set_link (anal->sdb_types, "linked_signature", f->addr),
		"exact function type link must be set");

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "exact linked signature must be readable");
	mu_assert_streq (signature->ret_type, "char", "exact link must take precedence over function name");
	mu_assert_eq ((int)r_list_length (signature->params), 1, "exact linked signature param count");
	r_anal_function_signature_free (signature);
	RAnalFunctionParam updated_param = { .name = "changed", .type = "short" };
	RList *updated_params = r_list_new ();
	mu_assert_notnull (updated_params, "Couldn't create updated linked param list");
	r_list_append (updated_params, &updated_param);
	RAnalFunctionSignature updated = {
		.ret_type = "short",
		.params = updated_params,
	};
	mu_assert_true (r_anal_function_set_signature (anal, f, &updated),
		"updating a linked signature must succeed");
	r_list_free (updated_params);
	mu_assert_streq (r_type_func_ret (anal->sdb_types, "linked_signature"), "short",
		"updating a linked function must update the linked type");

	mu_assert_true (r_anal_function_rename (f, "renamed_signature"), "function rename must succeed");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "exact linked signature must survive function rename");
	mu_assert_streq (signature->ret_type, "short", "renaming must not change exact linked signature");
	r_anal_function_signature_free (signature);

	mu_assert_true (r_type_unlink (anal->sdb_types, f->addr), "exact function type link must be removed");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "name-based signature must remain available after unlink");
	mu_assert_streq (signature->ret_type, "void", "unlink must restore name-based lookup");
	r_anal_function_signature_free (signature);

	sdb_set (anal->sdb_types, "not_a_function", "type", 0);
	mu_assert_true (r_type_set_link (anal->sdb_types, "not_a_function", f->addr),
		"non-function type link must be set for rejection test");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "non-function link must fall back to name-based signature");
	mu_assert_streq (signature->ret_type, "void", "non-function address link must be ignored");
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
	mu_assert_streq (signature->signature, "int sym.imp.__isoc99_scanf (const char *format, int *value);",
		"declaration must carry the function's own name, not the type db key");
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

bool test_r_anal_function_get_signature_string_resolves_import_flag_prototype(void) {
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
	// the prototype is resolved through the import flag, but the declaration
	// names the function so that an unedited afs! cannot rename it
	mu_assert_streq (sig, "int fcn.00003000 (const char *fmt);", "import flag must resolve canonical prototype");
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














typedef struct {
	RAnalFunction *fcn;
	RAnalVar *first;
	RAnalVar *second;
	const char *callconv;
	const char *first_name;
	const char *second_name;
	ut64 expected_epoch;
	int count;
	bool saw_complete_state;
} AtomicMutationEventState;

static void atomic_mutation_event_cb(REvent *event, int type, void *user, void *data) {
	AtomicMutationEventState *state = user;
	REventVariable *variable_event = data;
	state->count++;
	state->saw_complete_state = state->saw_complete_state
		&& type == R_EVENT_VARIABLE_NAME_CHANGED
		&& variable_event && variable_event->fcn == state->fcn
		&& variable_event->var
		&& !strcmp (state->fcn->callconv, state->callconv)
		&& !strcmp (state->first->name, state->first_name)
		&& !strcmp (state->second->name, state->second_name)
		&& r_anal_function_dirty_epoch (state->fcn) == state->expected_epoch;
}

static void atomic_mutation_count_event_cb(REvent *event, int type, void *user, void *data) {
	int *count = user;
	(*count)++;
}

static RAnal *atomic_mutation_test_anal_new(void) {
	RAnal *anal = r_anal_new ();
	if (anal) {
		anal->ev = r_event_new (anal);
		if (!anal->ev) {
			r_anal_free (anal);
			anal = NULL;
		}
	}
	return anal;
}

static void atomic_mutation_test_anal_free(RAnal *anal) {
	REvent *event = anal->ev;
	anal->ev = NULL;
	r_event_free (event);
	r_anal_free (anal);
}

typedef struct {
	size_t count;
	ut64 owner_addr;
	ut64 switch_addr;
} SwitchOwnershipProbe;

static bool switch_ownership_probe(RAnalFunction *fcn, RAnalBlock *block,
		RAnalSwitchOp *switch_op, void *user) {
	(void)fcn;
	SwitchOwnershipProbe *probe = user;
	probe->count++;
	probe->owner_addr = block->addr;
	probe->switch_addr = switch_op->jump_addr;
	return true;
}

// the walk reaches the indirect jump twice; the second arrival must not publish the switch on the start block

bool test_r_anal_function_overlapped_walk_keeps_one_switch_owner(void) {
	const ut64 addr = 0x1000;
	const char *hex =
		"554889e54883fe040f82990000004889f148c1e9024883f901750431c0eb644883e1fe31c066662e0f1f8400000000004469"
		"0407512d9ecc41c1c00f4569c09335871b4131d041c1c00d438d148081c2646b54e64469440704512d9ecc41c1c00f4569c0"
		"9335871b4131d041c1c00d438d148081c2646b54e64883c0084883c1fe75ad40f6c604741e690407512d9eccc1c00f69c093"
		"35871b31d0c1c00d8d148081c2646b54e64889f04883e0fc4189f04183e00331c94c8d0d5e0000004f6304814d01c841ffe0"
		"0fb64c0702c1e110440fb644070141c1e0084409c10fb6040731c869c0512d9eccc1c00f69c09335871b31c231d689f0c1e8"
		"1031f069c06bcaeb8589c1c1e90d31c169c935aeb2c289c8c1e81031c85dc30f1f00d8ffffffc1ffffffb4ffffffacffffff";
	size_t bytes_size = 0;
	ut8 *bytes = r_hex_str2bin_dup (hex, &bytes_size);
	mu_assert_notnull (bytes, "decode overlapping-switch fixture");
	mu_assert_eq (bytes_size, 300, "fixture contains function and jump table");
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create overlapping-switch analysis core");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://300",
		R_PERM_RWX, 0, addr), "open overlapping-switch analysis map");
	mu_assert_true (r_io_write_at (core->io, addr, bytes, bytes_size),
		"write overlapping-switch fixture");
	free (bytes);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	r_config_set_b (core->config, "anal.jmptbl", true);
	r_config_set_b (core->config, "anal.esil", false);
	(void)r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, 256);
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	mu_assert_notnull (fcn, "analysis creates overlapping-switch function");
	SwitchOwnershipProbe ownership = {0};
	mu_assert_true (r_anal_function_switches_foreach (
		fcn, switch_ownership_probe, &ownership), "enumerate switch owners");
	mu_assert_eq (ownership.count, 1, "one block owns the discovered switch");
	mu_assert_eq (ownership.owner_addr, addr + 167,
		"the indirect-jump block owns the discovered switch");
	mu_assert_eq (ownership.switch_addr, addr + 197,
		"switch ownership names the indirect jump");
	r_core_free (core);
	mu_end;
}

bool test_r_anal_apply_mutations_atomic_is_all_or_nothing(void) {
	RAnal *anal = atomic_mutation_test_anal_new ();
	mu_assert_notnull (anal, "create atomic mutation analysis");
	mu_assert_true (r_anal_cc_set (anal, "rax atomiccc(rdi)"), "seed atomic calling convention");
	RAnalFunction *fcn = r_anal_create_function (anal, "atomic_failure", 0x7100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create atomic mutation function");
	RAnalVar *var = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "int", 4, false, "before");
	mu_assert_notnull (var, "create atomic mutation variable");
	ut64 initial_epoch = r_anal_function_dirty_epoch (fcn);
	int event_count = 0;
	mu_assert_true (r_event_hook (anal->ev, R_EVENT_VARIABLE_NAME_CHANGED,
		atomic_mutation_count_event_cb, &event_count), "hook variable rename events");
	RAnalMutation mutations[] = {
		{
			.kind = R_ANAL_MUTATION_VAR_RENAME,
			.var = var,
			.name = "after",
		},
		{
			.kind = R_ANAL_MUTATION_CALLCONV,
			.fcn = fcn,
			.callconv = "missingcc",
		},
	};
	RAnalMutationAtomicResult result = r_anal_apply_mutations_atomic (anal, mutations, R_ARRAY_SIZE (mutations));
	mu_assert_eq (result.status, R_ANAL_MUTATION_ATOMIC_STATUS_VALIDATION_FAILED, "invalid record rejects atomic batch");
	mu_assert_eq (result.failed_index, 1, "invalid record index");
	mu_assert_eq (result.validated, 1, "validated prefix count");
	mu_assert_eq (result.committed, 0, "failed batch commits nothing");
	mu_assert_streq (var->name, "before", "earlier valid rename stays unapplied");
	mu_assert_null (fcn->callconv, "invalid callconv stays unapplied");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), initial_epoch, "failed batch does not publish an epoch");
	mu_assert_eq (event_count, 0, "failed batch does not publish events");
	atomic_mutation_test_anal_free (anal);
	mu_end;
}

bool test_r_anal_apply_mutations_atomic_rejects_unsupported_preflight(void) {
	RAnal *anal = atomic_mutation_test_anal_new ();
	mu_assert_notnull (anal, "create unsupported mutation analysis");
	RAnalFunction *fcn = r_anal_create_function (anal, "atomic_unsupported", 0x7200, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create unsupported mutation function");
	RAnalVar *var = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "int", 4, false, "before");
	mu_assert_notnull (var, "create unsupported mutation variable");
	ut64 initial_epoch = r_anal_function_dirty_epoch (fcn);
	int event_count = 0;
	mu_assert_true (r_event_hook (anal->ev, R_EVENT_VARIABLE_NAME_CHANGED,
		atomic_mutation_count_event_cb, &event_count), "hook unsupported rename events");
	RAnalMutationKind unsupported[] = {
		R_ANAL_MUTATION_FLAG,
		R_ANAL_MUTATION_TYPE_DECL,
		R_ANAL_MUTATION_VAR,
		R_ANAL_MUTATION_VAR_TYPE,
		R_ANAL_MUTATION_SIGNATURE,
		R_ANAL_MUTATION_XREF,
		R_ANAL_MUTATION_COMMENT,
		R_ANAL_MUTATION_TYPE_LINK,
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (unsupported); i++) {
		RAnalMutation mutations[] = {
			{
				.kind = R_ANAL_MUTATION_VAR_RENAME,
				.var = var,
				.name = "after",
			},
			{
				.kind = unsupported[i],
			},
		};
		RAnalMutationAtomicResult result = r_anal_apply_mutations_atomic (
			anal, mutations, R_ARRAY_SIZE (mutations));
		mu_assert_eq (result.status, R_ANAL_MUTATION_ATOMIC_STATUS_UNSUPPORTED, "unsupported kind rejects preflight");
		mu_assert_eq (result.failed_index, 1, "unsupported record index");
		mu_assert_eq (result.validated, 0, "unsupported scan precedes validation");
		mu_assert_eq (result.committed, 0, "unsupported batch commits nothing");
		mu_assert_streq (var->name, "before", "unsupported batch leaves valid prefix untouched");
	}
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), initial_epoch, "unsupported batches do not publish epochs");
	mu_assert_eq (event_count, 0, "unsupported batches do not publish events");
	atomic_mutation_test_anal_free (anal);
	mu_end;
}

bool test_r_anal_apply_mutations_atomic_rolls_back_commit_conflict(void) {
	RAnal *anal = atomic_mutation_test_anal_new ();
	mu_assert_notnull (anal, "create rollback analysis");
	RAnalFunction *fcn = r_anal_create_function (anal, "atomic_rollback", 0x7300, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create rollback function");
	RAnalVar *var = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "int", 4, false, "before");
	mu_assert_notnull (var, "create rollback variable");
	ut64 initial_epoch = r_anal_function_dirty_epoch (fcn);
	int event_count = 0;
	mu_assert_true (r_event_hook (anal->ev, R_EVENT_VARIABLE_NAME_CHANGED,
		atomic_mutation_count_event_cb, &event_count), "hook rollback rename events");
	RAnalMutation mutations[] = {
		{
			.kind = R_ANAL_MUTATION_VAR_RENAME,
			.var = var,
			.name = "first_write",
		},
		{
			.kind = R_ANAL_MUTATION_VAR_RENAME,
			.var = var,
			.name = "conflicting_write",
		},
	};
	RAnalMutationAtomicResult result = r_anal_apply_mutations_atomic (anal, mutations, R_ARRAY_SIZE (mutations));
	mu_assert_eq (result.status, R_ANAL_MUTATION_ATOMIC_STATUS_COMMIT_FAILED, "write conflict fails guarded commit");
	mu_assert_eq (result.failed_index, 1, "conflicting write index");
	mu_assert_eq (result.validated, 2, "both conflicting records validate against entry state");
	mu_assert_eq (result.committed, 0, "rolled-back batch reports no committed records");
	mu_assert_streq (var->name, "before", "first pointer swap is rolled back");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), initial_epoch, "rollback does not publish an epoch");
	mu_assert_eq (event_count, 0, "rollback does not publish events");
	atomic_mutation_test_anal_free (anal);
	mu_end;
}

bool test_r_anal_apply_mutations_atomic_defers_publication(void) {
	RAnal *anal = atomic_mutation_test_anal_new ();
	mu_assert_notnull (anal, "create publication analysis");
	mu_assert_true (r_anal_cc_set (anal, "rax atomica(rdi)"), "seed initial atomic calling convention");
	mu_assert_true (r_anal_cc_set (anal, "rax atomicb(rsi)"), "seed replacement atomic calling convention");
	RAnalFunction *fcn = r_anal_create_function (anal, "atomic_publication", 0x7400, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create publication function");
	mu_assert_true (r_anal_function_set_callconv (anal, fcn, "atomica"), "set initial calling convention");
	RAnalVar *first = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "int", 4, false, "first");
	RAnalVar *second = r_anal_function_set_var (fcn, -16, R_ANAL_VAR_KIND_BPV, "int", 4, false, "second");
	mu_assert_notnull (first, "create first publication variable");
	mu_assert_notnull (second, "create second publication variable");
	ut64 initial_epoch = r_anal_function_dirty_epoch (fcn);
	AtomicMutationEventState event_state = {
		.fcn = fcn,
		.first = first,
		.second = second,
		.callconv = "atomicb",
		.first_name = "renamed_first",
		.second_name = "renamed_second",
		.expected_epoch = initial_epoch + 1,
		.saw_complete_state = true,
	};
	int function_modified_events = 0;
	mu_assert_true (r_event_hook (anal->ev, R_EVENT_VARIABLE_NAME_CHANGED,
		atomic_mutation_event_cb, &event_state), "hook deferred rename events");
	mu_assert_true (r_event_hook (anal->ev, R_EVENT_FUNCTION_MODIFIED,
		atomic_mutation_count_event_cb, &function_modified_events), "hook function modified events");
	anal->is_dirty = false;
	RAnalMutation mutations[] = {
		{
			.kind = R_ANAL_MUTATION_VAR_RENAME,
			.var = first,
			.name = "renamed_first",
		},
		{
			.kind = R_ANAL_MUTATION_CALLCONV,
			.fcn = fcn,
			.callconv = "atomicb",
		},
		{
			.kind = R_ANAL_MUTATION_VAR_RENAME,
			.var = second,
			.name = "renamed_second",
		},
	};
	RAnalMutationAtomicResult result = r_anal_apply_mutations_atomic (anal, mutations, R_ARRAY_SIZE (mutations));
	mu_assert_eq (result.status, R_ANAL_MUTATION_ATOMIC_STATUS_OK, "atomic batch commits");
	mu_assert_eq (result.failed_index, R_ANAL_MUTATION_ATOMIC_INDEX_NONE, "successful batch has no failed index");
	mu_assert_eq (result.validated, 3, "successful batch validates every record");
	mu_assert_eq (result.committed, 3, "successful batch commits every record");
	mu_assert_streq (fcn->callconv, "atomicb", "calling convention pointer swap commits");
	mu_assert_streq (first->name, "renamed_first", "first rename commits");
	mu_assert_streq (second->name, "renamed_second", "second rename commits");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), initial_epoch + 1, "changed function epoch publishes exactly once");
	mu_assert_true (anal->is_dirty, "successful changed batch marks analysis dirty");
	mu_assert_eq (event_state.count, 2, "one event is published for each changed rename");
	mu_assert_true (event_state.saw_complete_state, "rename events observe the fully committed batch and published epoch");
	mu_assert_eq (function_modified_events, 0, "callconv mutation does not invent a function event");
	atomic_mutation_test_anal_free (anal);
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
	mu_run_test (test_r_core_anal_fcn_variadic_marker_requires_unclobbered_al);
	mu_run_test (test_r_anal_function_get_signature);
	mu_run_test (test_r_anal_function_get_signature_prefers_exact_type_link);
	mu_run_test (test_r_anal_function_set_signature_uses_canonical_type_name);
	mu_run_test (test_r_anal_function_get_signature_string_resolves_import_flag_prototype);
	mu_run_test (test_r_anal_function_get_signature_uses_basename_for_dbg_prefixed_function);
	mu_run_test (test_r_anal_function_get_signature_string_falls_back_to_vars);
	mu_run_test (test_r_anal_function_get_signature_string_hides_variadic_placeholder);
	mu_run_test (test_r_anal_function_get_signature_falls_back_to_valid_callconv);
	mu_run_test (test_r_anal_apply_mutations_atomic_is_all_or_nothing);
	mu_run_test (test_r_anal_apply_mutations_atomic_rejects_unsupported_preflight);
	mu_run_test (test_r_anal_apply_mutations_atomic_rolls_back_commit_conflict);
	mu_run_test (test_r_anal_apply_mutations_atomic_defers_publication);
	mu_run_test (test_r_anal_function_switches_foreach);
	mu_run_test (test_r_anal_function_overlapped_walk_keeps_one_switch_owner);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
