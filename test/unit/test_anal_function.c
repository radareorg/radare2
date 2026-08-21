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

static RCore *snapshot_test_core_new(void) {
	RCore *core = r_core_new ();
	if (!core) {
		return NULL;
	}
	if (!r_io_open_at (core->io, "malloc://1048576", R_PERM_RW, 0, 0)) {
		r_core_free (core);
		return NULL;
	}
	return core;
}

static bool snapshot_test_ensure_block(RAnal *anal, RAnalFunction *fcn, ut64 size) {
	if (fcn->bbs && r_list_length (fcn->bbs)) {
		return true;
	}
	RAnalBlock *block = r_anal_create_block (anal, fcn->addr, size);
	if (!block) {
		return false;
	}
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	return true;
}

static bool set_function_type_link(RAnal *anal, const char *type, ut64 addr);

static bool snapshot_test_publish_owned_function_link(RAnal *anal, RAnalFunction *fcn) {
	return set_function_type_link (anal, fcn->name, fcn->addr)
		&& r_anal_dwarf_function_link_mark_poisoned (
			anal, fcn->addr, fcn->name)
		&& r_anal_function_type_link_set_owned (
			anal, fcn->name, fcn->addr)
		&& r_anal_dwarf_function_link_publish_owned (
			anal, fcn->addr, fcn->name);
}

static bool snapshot_test_publish_frame_pointer(RAnal *anal,
		RAnalFunction *fcn, const char *reg_name) {
	HtUP *proofs = r_anal_dwarf_frame_pointer_proofs_new ();
	if (!proofs) {
		return false;
	}
	bool prepared = true;
	if (R_STR_ISNOTEMPTY (reg_name)) {
		const int dwarf_reg_num = !strcmp (reg_name, "rbp")
			? 6: (!strcmp (reg_name, "rsp")? 7: -1);
		RRegItem *reg = r_reg_get (anal->reg, reg_name, -1);
		prepared = dwarf_reg_num >= 0 && reg
			&& reg->offset >= 0 && !(reg->offset % 8)
			&& reg->size > 0 && !(reg->size % 8)
			&& r_anal_dwarf_frame_pointer_proof_add (
				proofs, fcn->addr, fcn->name, anal->config->arch,
				anal->config->bits, dwarf_reg_num, reg_name,
				(ut64)(reg->offset / 8), (ut32)(reg->size / 8));
		r_unref (reg);
	}
	if (prepared && r_anal_dwarf_frame_pointer_proofs_publish (anal, proofs)) {
		return true;
	}
	r_anal_dwarf_frame_pointer_proofs_free (proofs);
	return false;
}

static int snapshot_lazy_cc_calls;

static const char *snapshot_lazy_cc(RBin *bin, ut64 addr) {
	(void)bin;
	(void)addr;
	snapshot_lazy_cc_calls++;
	return "cdecl";
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

	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (slot && slot->name && !strcmp (slot->name, name)) {
			return slot;
		}
	}
	return NULL;
}

static bool set_function_type_link(RAnal *anal, const char *type, ut64 addr) {
	RAnalMutation mutation = {
		.kind = R_ANAL_MUTATION_TYPE_LINK,
		.type = type,
		.addr = addr,
	};
	return r_anal_apply_mutations (anal, &mutation, 1, NULL);
}

static RAnalBaseType *find_snapshot_base_type(const RAnalFunctionSnapshot *snapshot, const char *name) {
	RListIter *iter;
	RAnalBaseType *type;
	r_list_foreach (snapshot->base_types, iter, type) {
		if (type && type->name && !strcmp (type->name, name)) {
			return type;
		}
	}
	return NULL;
}

static RAnalBaseType *find_snapshot_base_type_kind(const RAnalFunctionSnapshot *snapshot, const char *name, RAnalBaseTypeKind kind) {
	RListIter *iter;
	RAnalBaseType *type;
	r_list_foreach (snapshot->base_types, iter, type) {
		if (type && type->kind == kind && type->name && !strcmp (type->name, name)) {
			return type;
		}
	}
	return NULL;
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

static bool test_r_anal_function_snapshot_reads_current_state_only(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create read-only snapshot analysis");
	RAnalFunction *caller = r_anal_create_function (
		anal, "snapshot_current_caller", 0x6600, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *callee = r_anal_create_function (
		anal, "snapshot_current_callee", 0x6700, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (caller, "create read-only snapshot caller");
	mu_assert_notnull (callee, "create read-only snapshot callee");
	mu_assert_true (snapshot_test_ensure_block (anal, caller, 0x20),
		"back caller with exact bytes");
	caller->callconv = r_str_constpool_get (&anal->constpool, "dyncc");
	anal->binb.get_cc = snapshot_lazy_cc;
	snapshot_lazy_cc_calls = 0;
	mu_assert_true (r_anal_xrefs_setf (
		anal, caller, 0x6610, callee->addr, R_ANAL_REF_TYPE_CALL),
		"record current-state callee");
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	priv->types_dirty = true;
	priv->types_loaded_bits = 0;
	ut64 function_epoch = r_anal_function_dirty_epoch (caller);
	ut64 type_epoch = r_anal_types_dirty_epoch (anal);

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, caller, NULL);
	mu_assert_eq (snapshot_lazy_cc_calls, 0,
		"snapshot does not resolve a lazy calling convention");
	mu_assert_streq (caller->callconv, "dyncc",
		"snapshot leaves the live calling convention untouched");
	mu_assert_true (priv->types_dirty,
		"snapshot does not lazily load the type database for callees");
	mu_assert_eq (priv->types_loaded_bits, 0,
		"snapshot leaves the current type-load state untouched");
	mu_assert_eq (r_anal_function_dirty_epoch (caller), function_epoch,
		"snapshot does not publish a function mutation");
	mu_assert_eq (r_anal_types_dirty_epoch (anal), type_epoch,
		"snapshot does not publish a type mutation");
	mu_assert_notnull (snapshot, "collect read-only current-state snapshot");
	mu_assert_false (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"unresolved current calling convention remains inexact");
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

static bool test_r_anal_function_snapshot_does_not_mutate_var_cache(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create read-only variable-cache analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax readonlycc(rdi)"),
		"seed read-only variable-cache calling convention");
	RAnalFunction *fcn = r_anal_create_function (
		anal, "snapshot_var_cache", 0x6800, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create read-only variable-cache function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back variable-cache function with exact bytes");
	fcn->callconv = r_str_constpool_get (&anal->constpool, "readonlycc");
	const int rdi = reg_index (anal, "rdi");
	mu_assert ("rdi register index must resolve", rdi >= 0);
	RAnalVar *arg = r_anal_function_set_var (
		fcn, rdi, R_ANAL_VAR_KIND_REG, "int", 4, true, "arg0");
	mu_assert_notnull (arg, "create default-named register argument");
	mu_assert_eq (arg->argnum, -1, "live argument index starts unresolved");
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect read-only variable-cache snapshot");
	RAnalFcnRegArg *snapshot_arg = find_register_param (&snapshot->context, "rdi");
	mu_assert_notnull (snapshot_arg, "snapshot owns the register argument");
	mu_assert_eq (snapshot_arg->arg_index, 0,
		"snapshot derives the argument index without publishing it");
	mu_assert_eq (arg->argnum, -1,
		"snapshot leaves the live argument index unresolved");
	mu_assert_streq (arg->name, "arg0",
		"snapshot leaves the live default argument name untouched");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch,
		"snapshot leaves the live function revision untouched");
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
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
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax ctxcall(rdi, rdx, stack)"), "Couldn't seed test-local calling convention");

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn_ctx", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "Couldn't create function for function-context test");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back function-context fixture with exact bytes");
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
	mu_assert_true (set_function_type_link (anal, fcn->name, fcn->addr),
		"link function-context signature by address");
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

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect typed function snapshot");
	RAnalFcnContext *ctx = &snapshot->context;
	mu_assert_eq (snapshot->schema_version, R_ANAL_FUNCTION_SNAPSHOT_SCHEMA_VERSION, "snapshot schema version");
	mu_assert_eq (snapshot->struct_size, sizeof (RAnalFunctionSnapshot), "snapshot structure size");
	mu_assert_eq (snapshot->function_addr, fcn->addr, "snapshot function address");
	mu_assert_streq (snapshot->function_name, fcn->name, "snapshot function name");
	mu_assert_notnull (snapshot->base_types, "snapshot owns a type-layout list");
	mu_assert_neq (snapshot->revision_identity, 0, "snapshot revision identity");
	mu_assert_eq (ctx->context_hash, snapshot->revision_identity, "legacy hash aliases snapshot revision");
	mu_assert_eq (r_anal_function_context_hash (anal, fcn), snapshot->revision_identity, "compatibility hash is snapshot-derived");

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
	mu_assert_eq (home_ctx->home_reg_offset,
		snapshot->function_interface.parameters[0].storage.offset,
		"param-home slot must keep canonical source-register offset");
	mu_assert_eq (home_ctx->home_reg_size,
		snapshot->function_interface.parameters[0].storage.size,
		"param-home slot must keep canonical source-register size");
	mu_assert_false (snapshot->function_interface.stack_slot_roles_complete,
		"unsupported stack arguments reject exact stack-slot roles");
	mu_assert_false (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES,
		"unsupported stack arguments omit exact stack-slot-role capability");

	mu_assert_eq (stack_arg_ctx->role, R_ANAL_FCN_SLOT_ARG, "stack arg slot must stay stack-arg");
	mu_assert_eq (stack_arg_ctx->arg_index, -1, "stack arg slot must not synthesize param indexes from sparse register args");
	mu_assert_null (stack_arg_ctx->arg_name, "stack arg slot must not synthesize a signature param name without a canonical index");

	mu_assert_eq (saved_ctx->role, R_ANAL_FCN_SLOT_LOCAL, "saved-named local must not be reclassified from its spelling");
	mu_assert_eq (arg_named_local_ctx->role, R_ANAL_FCN_SLOT_LOCAL, "arg-named local must not become a param-home without a proven register home");

	ut64 old_revision = snapshot->revision_identity;
	char *snapshot_reg_arg_name = strdup (r_str_get (rdx_param->name));
	mu_assert_notnull (snapshot_reg_arg_name, "copy snapshot register-argument name");
	ut64 old_function_epoch = r_anal_function_dirty_epoch (fcn);
	mu_assert_true (r_anal_var_rename (anal, home_source, "renamed_arg1"), "rename through revision-aware API");
	mu_assert_neq (r_anal_function_dirty_epoch (fcn), old_function_epoch,
		"variable rename bumps the function revision epoch");
	mu_assert_streq (rdx_param->name, snapshot_reg_arg_name, "collected snapshot remains immutable after live mutation");
	free (snapshot_reg_arg_name);
	RAnalFunctionSnapshot *next = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (next, "collect snapshot after live mutation");
	mu_assert_neq (next->revision_identity, old_revision, "live mutation changes snapshot revision");
	r_anal_function_snapshot_free (next);

	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

static bool test_r_anal_function_snapshot_distinguishes_split_fallthrough(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create snapshot CFG analysis");
	mu_assert_true (r_anal_use (anal, "x86"), "select x86 snapshot CFG analyzer");
	r_anal_set_bits (anal, 64);

	const ut8 split_bytes[] = { 0xc7, 0x45, 0xfc, 0, 0, 0, 0, 0xc3 };
	const ut64 split_addr = 0x1800;
	mu_assert_true (r_io_write_at (core->io, split_addr, split_bytes,
		sizeof (split_bytes)), "write split-fallthrough machine bytes");
	RAnalFunction *split_fcn = r_anal_create_function (
		anal, "split_fallthrough", split_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (split_fcn, "create split-fallthrough function");
	RAnalBlock *whole = r_anal_create_block (anal, split_addr, sizeof (split_bytes));
	mu_assert_notnull (whole, "create block before split");
	r_anal_function_add_block (split_fcn, whole);
	RAnalBlock *tail = r_anal_block_split (whole, split_addr + 7);
	mu_assert_notnull (tail, "split sequential block before return");
	mu_assert_eq (whole->jump, split_addr + 7, "split records structural successor in jump");
	r_unref (tail);
	r_unref (whole);

	RAnalFunctionSnapshot *split_snapshot = r_anal_function_snapshot_collect_bounded (
		anal, split_fcn, NULL);
	mu_assert_notnull (split_snapshot, "collect split-fallthrough snapshot");
	RAnalSnapshotSuccessorView successor = {0};
	mu_assert_true (r_anal_function_snapshot_successor_view (
		split_snapshot, 0, 0, &successor), "read split-fallthrough successor");
	mu_assert_eq (successor.kind, R_ANAL_SNAPSHOT_SUCCESSOR_FALLTHROUGH,
		"MOV-only split block has a machine-sequential successor");
	mu_assert_eq (successor.target_addr, split_addr + 7,
		"split fallthrough keeps the exact block-end target");
	r_anal_function_snapshot_free (split_snapshot);

	const ut8 branch_bytes[] = { 0xeb, 0, 0xc3 };
	const ut64 branch_addr = 0x2800;
	mu_assert_true (r_io_write_at (core->io, branch_addr, branch_bytes,
		sizeof (branch_bytes)), "write branch-to-next machine bytes");
	RAnalFunction *branch_fcn = r_anal_create_function (
		anal, "branch_to_next", branch_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (branch_fcn, "create branch-to-next function");
	RAnalBlock *branch = r_anal_create_block (anal, branch_addr, 2);
	RAnalBlock *branch_tail = r_anal_create_block (anal, branch_addr + 2, 1);
	mu_assert_notnull (branch, "create explicit branch block");
	mu_assert_notnull (branch_tail, "create explicit branch target block");
	branch->jump = branch_addr + 2;
	r_anal_function_add_block (branch_fcn, branch);
	r_anal_function_add_block (branch_fcn, branch_tail);
	r_unref (branch);
	r_unref (branch_tail);

	RAnalFunctionSnapshot *branch_snapshot = r_anal_function_snapshot_collect_bounded (
		anal, branch_fcn, NULL);
	mu_assert_notnull (branch_snapshot, "collect branch-to-next snapshot");
	mu_assert_true (r_anal_function_snapshot_successor_view (
		branch_snapshot, 0, 0, &successor), "read branch-to-next successor");
	mu_assert_eq (successor.kind, R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT,
		"explicit branch-to-next remains a direct successor");
	mu_assert_eq (successor.target_addr, branch_addr + 2,
		"explicit branch keeps its exact target");
	r_anal_function_snapshot_free (branch_snapshot);

	const ut8 conditional_bytes[] = { 0x74, 0, 0xc3 };
	const ut64 conditional_addr = 0x3800;
	mu_assert_true (r_io_write_at (core->io, conditional_addr, conditional_bytes,
		sizeof (conditional_bytes)), "write conditional branch-to-next bytes");
	RAnalFunction *conditional_fcn = r_anal_create_function (
		anal, "incomplete_conditional", conditional_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (conditional_fcn, "create incomplete conditional function");
	RAnalBlock *conditional = r_anal_create_block (anal, conditional_addr, 2);
	RAnalBlock *conditional_tail = r_anal_create_block (anal, conditional_addr + 2, 1);
	mu_assert_notnull (conditional, "create conditional branch block");
	mu_assert_notnull (conditional_tail, "create conditional target block");
	conditional->jump = conditional_addr + 2;
	r_anal_function_add_block (conditional_fcn, conditional);
	r_anal_function_add_block (conditional_fcn, conditional_tail);
	r_unref (conditional);
	r_unref (conditional_tail);
	mu_assert_null (r_anal_function_snapshot_collect_bounded (anal, conditional_fcn, NULL),
		"sole conditional edge cannot masquerade as direct or fallthrough");

	const ut8 indirect_bytes[] = { 0xff, 0xe0, 0xc3 };
	const ut64 indirect_addr = 0x4800;
	mu_assert_true (r_io_write_at (core->io, indirect_addr, indirect_bytes,
		sizeof (indirect_bytes)), "write indirect branch bytes");
	RAnalFunction *indirect_fcn = r_anal_create_function (
		anal, "incomplete_indirect", indirect_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (indirect_fcn, "create incomplete indirect function");
	RAnalBlock *indirect = r_anal_create_block (anal, indirect_addr, 2);
	RAnalBlock *indirect_tail = r_anal_create_block (anal, indirect_addr + 2, 1);
	mu_assert_notnull (indirect, "create indirect branch block");
	mu_assert_notnull (indirect_tail, "create indirect target block");
	indirect->jump = indirect_addr + 2;
	r_anal_function_add_block (indirect_fcn, indirect);
	r_anal_function_add_block (indirect_fcn, indirect_tail);
	r_unref (indirect);
	r_unref (indirect_tail);
	// An unresolved indirect branch exits the block without naming where it
	// goes, so the edge the analysis recorded to the next address is dropped
	// rather than captured as a transfer the instruction contradicts. One such
	// branch does not discard the function. What must never happen is the
	// recorded edge surviving as a direct or fallthrough successor.
	RAnalFunctionSnapshot *indirect_snapshot = r_anal_function_snapshot_collect_bounded (
		anal, indirect_fcn, NULL);
	mu_assert_notnull (indirect_snapshot,
		"one unresolved branch does not discard the whole function");
	RAnalSnapshotBlockView indirect_view = {0};
	mu_assert_true (r_anal_function_snapshot_block_view (
		indirect_snapshot, 0, &indirect_view), "read the indirect branch block");
	mu_assert_eq (indirect_view.addr, indirect_addr,
		"the first block is the one ending in the indirect branch");
	mu_assert_eq (indirect_view.num_successors, 0,
		"indirect edge cannot masquerade as direct or fallthrough");
	mu_assert_false (r_anal_function_snapshot_successor_view (
		indirect_snapshot, 0, 0, &successor),
		"the dropped indirect edge is not readable as a successor");
	r_anal_function_snapshot_free (indirect_snapshot);

	anal->config->endian = R_SYS_ENDIAN_BIG;
	r_anal_set_bits (anal, 32);
	mu_assert_true (r_anal_use (anal, "mips"), "select MIPS delay-slot analyzer");
	const ut8 delay_bytes[] = {
		0x08, 0x00, 0x16, 0x02, // j 0x5808
		0x00, 0x00, 0x00, 0x00, // delay-slot nop
		0x03, 0xe0, 0x00, 0x08, // jr ra
		0x00, 0x00, 0x00, 0x00, // delay-slot nop
	};
	const ut64 delay_addr = 0x5800;
	mu_assert_true (r_io_write_at (core->io, delay_addr, delay_bytes,
		sizeof (delay_bytes)), "write delayed branch-to-next bytes");
	RAnalFunction *delay_fcn = r_anal_create_function (
		anal, "delayed_branch_to_next", delay_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (delay_fcn, "create delayed branch-to-next function");
	RAnalBlock *delay = r_anal_create_block (anal, delay_addr, 8);
	RAnalBlock *delay_tail = r_anal_create_block (anal, delay_addr + 8, 8);
	mu_assert_notnull (delay, "create delayed branch block");
	mu_assert_notnull (delay_tail, "create delayed branch target block");
	delay->jump = delay_addr + 8;
	r_anal_function_add_block (delay_fcn, delay);
	r_anal_function_add_block (delay_fcn, delay_tail);
	r_unref (delay);
	r_unref (delay_tail);
	RAnalFunctionSnapshot *delay_snapshot = r_anal_function_snapshot_collect_bounded (
		anal, delay_fcn, NULL);
	mu_assert_notnull (delay_snapshot, "collect delayed branch-to-next snapshot");
	mu_assert_true (r_anal_function_snapshot_successor_view (
		delay_snapshot, 0, 0, &successor), "read delayed branch successor");
	mu_assert_eq (successor.kind, R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT,
		"delay-slot instruction cannot demote the effective direct terminator");
	r_anal_function_snapshot_free (delay_snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_limits_bound_type_clone(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create bounded snapshot analysis");
	sdb_reset (anal->sdb_types);
	RAnalFunction *fcn = r_anal_create_function (
		anal, "bounded_snapshot", 0x6800, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create bounded snapshot function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back bounded snapshot with exact bytes");

	RAnalBaseType *atomic = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	atomic->name = strdup ("limit_u8");
	atomic->type = strdup ("u");
	atomic->size = 8;
	r_anal_save_base_type (anal, atomic);
	r_anal_base_type_free (atomic);

	RAnalBaseType *composite = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	composite->name = strdup ("limit_pair");
	RAnalStructMember member = {
		.name = strdup ("field"),
		.type = strdup ("limit_u8"),
	};
	RVecAnalTypeMember_push_back (&composite->struct_data.members, &member);
	r_anal_save_base_type (anal, composite);
	r_anal_base_type_free (composite);
	RAnalBaseType *enumeration = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	enumeration->name = strdup ("limit_choice");
	RAnalEnumCase cas = {
		.name = strdup ("yes"),
		.val = 1,
	};
	RVecAnalEnumCase_push_back (&enumeration->enum_data.cases, &cas);
	r_anal_save_base_type (anal, enumeration);
	r_anal_base_type_free (enumeration);
	RAnalBaseType *alias = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	alias->name = strdup ("limit_alias");
	alias->type = strdup ("limit_u8");
	r_anal_save_base_type (anal, alias);
	r_anal_base_type_free (alias);
	/* Real type databases can contain a root kind marker whose payload was
	 * intentionally omitted. It is not a cloneable base type and must be
	 * skipped consistently by both the bounded preflight and clone. */
	sdb_set (anal->sdb_types, "incomplete_atomic", "type", 0);

	const size_t exact_string_bytes = sizeof ("limit_u8") + sizeof ("u")
		+ sizeof ("limit_pair") + sizeof ("field") + sizeof ("limit_u8")
		+ sizeof ("limit_choice") + sizeof ("yes")
		+ sizeof ("limit_alias") + sizeof ("limit_u8");
	RAnalFunctionSnapshotLimits limits;
	r_anal_function_snapshot_limits_default (&limits);
	limits.max_base_types = 4;
	limits.max_base_type_children = 2;
	limits.max_base_type_string_bytes = exact_string_bytes;
	limits.max_assumptions_json_bytes = sizeof ("[]");
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_with_limits (
		anal, fcn, &limits, NULL);
	mu_assert_notnull (snapshot, "exact type count and byte bounds succeed");
	mu_assert_eq (r_list_length (snapshot->base_types), 4,
		"root/namespace duplicates and payload-less markers are not charged");
	mu_assert_null (find_snapshot_base_type (snapshot, "incomplete_atomic"),
		"payload-less type marker is not exposed as a partial base type");
	RAnalBaseType *snapshot_atomic = find_snapshot_base_type (snapshot, "limit_u8");
	mu_assert_notnull (snapshot_atomic, "bounded snapshot owns atomic type");
	mu_assert_streq (snapshot_atomic->type, "u", "bounded snapshot owns atomic declaration");
	RAnalBaseType *snapshot_enum = find_snapshot_base_type (snapshot, "limit_choice");
	mu_assert_notnull (snapshot_enum, "bounded snapshot owns enum type");
	mu_assert_eq (RVecAnalEnumCase_length (&snapshot_enum->enum_data.cases), 1,
		"exact child bound includes enum variants");
	mu_assert_streq (RVecAnalEnumCase_at (&snapshot_enum->enum_data.cases, 0)->name,
		"yes", "enum variant name is owned");
	RAnalBaseType *snapshot_alias = find_snapshot_base_type (snapshot, "limit_alias");
	mu_assert_notnull (snapshot_alias, "bounded snapshot owns typedef");
	mu_assert_streq (snapshot_alias->type, "limit_u8", "typedef target string is owned");
	ut64 revision = snapshot->revision_identity;

	RAnalFunctionSnapshotLimits rejected = limits;
	rejected.max_base_types--;
	mu_assert_null (r_anal_function_snapshot_collect_with_limits (anal, fcn, &rejected, NULL),
		"base-type count rejects before constructing a partial snapshot");
	rejected = limits;
	rejected.max_base_type_children--;
	mu_assert_null (r_anal_function_snapshot_collect_with_limits (anal, fcn, &rejected, NULL),
		"member count rejects before constructing a partial snapshot");
	rejected = limits;
	rejected.max_base_type_string_bytes--;
	mu_assert_null (r_anal_function_snapshot_collect_with_limits (anal, fcn, &rejected, NULL),
		"owned type bytes reject before cloning strings");
	rejected = limits;
	rejected.max_assumptions_json_bytes--;
	mu_assert_null (r_anal_function_snapshot_collect_with_limits (anal, fcn, &rejected, NULL),
		"assumptions JSON bytes reject before snapshot allocation");
	rejected = limits;
	rejected.struct_size--;
	mu_assert_null (r_anal_function_snapshot_collect_with_limits (anal, fcn, &rejected, NULL),
		"truncated limits contract is rejected");

	RAnalFunctionSnapshotLimits unbounded = limits;
	unbounded.max_base_types = SIZE_MAX;
	mu_assert_null (r_anal_function_snapshot_collect_with_limits (
		anal, fcn, &unbounded, NULL), "SIZE_MAX authority ceiling is rejected");

	atomic = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	atomic->name = strdup ("limit_u8");
	atomic->type = strdup ("v");
	atomic->size = 8;
	r_anal_save_base_type (anal, atomic);
	r_anal_base_type_free (atomic);
	mu_assert_streq (snapshot_atomic->type, "u", "live type mutation cannot alter owned snapshot");
	RAnalFunctionSnapshot *next = r_anal_function_snapshot_collect_with_limits (
		anal, fcn, &limits, NULL);
	mu_assert_notnull (next, "collect bounded snapshot after type mutation");
	RAnalBaseType *next_atomic = find_snapshot_base_type (next, "limit_u8");
	mu_assert_notnull (next_atomic, "mutated atomic type remains in new snapshot");
	mu_assert_streq (next_atomic->type, "v", "new bounded snapshot observes live mutation");
	mu_assert_neq (next->revision_identity, revision,
		"bounded snapshot revision changes with type epoch and content");
	r_anal_function_snapshot_free (next);
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_seals_exact_register_interface(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax exactcc(rdi)"), "seed exact calling convention");
	sdb_set (anal->sdb_cc, "cc.exactcc.retmech", "stack:0:8:8", 0);
	sdb_set (anal->sdb_cc, "cc.exactcc.stackalloc", "lower", 0);
	sdb_set (anal->sdb_cc, "cc.exactcc.redzone", "128", 0);

	RAnalFunction *fcn = r_anal_create_function (anal, "exact_snapshot", 0x7000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create exact snapshot function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back exact interface with exact bytes");
	RAnalFunctionParam parameter = {
		.name = "value",
		.type = "int64_t",
	};
	RList *parameters = r_list_new ();
	mu_assert_notnull (parameters, "create exact parameter list");
	mu_assert_true (r_list_append (parameters, &parameter), "append exact parameter");
	RAnalFunctionSignature signature = {
		.ret_type = "int64_t",
		.callconv = "exactcc",
		.params = parameters,
	};
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature), "apply exact signature");
	r_list_free (parameters);
	RAnalFunctionSnapshot *name_only = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (name_only, "collect name-only signature snapshot");
	mu_assert_true (name_only->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_SIGNATURE,
		"name lookup remains available for ordinary signatures");
	mu_assert_false (name_only->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"name-only signature cannot certify an exact interface");
	ut64 link_epoch = r_anal_types_dirty_epoch (anal);
	ut64 link_hash = r_anal_types_context_hash (anal);
	r_anal_function_snapshot_free (name_only);
	mu_assert_true (set_function_type_link (anal, fcn->name, fcn->addr),
		"link exact signature by address");
	mu_assert_neq (r_anal_types_dirty_epoch (anal), link_epoch,
		"function link bumps the type epoch");
	mu_assert_neq (r_anal_types_context_hash (anal), link_hash,
		"function link changes the type context hash");
	mu_assert_true (r_anal_function_has_address_linked_signature_current (fcn),
		"ordinary address link remains authoritative without private ownership");
	mu_assert_true (r_anal_dwarf_function_link_mark_poisoned (
		anal, fcn->addr, fcn->name), "prepare parser-owned address link");
	mu_assert_false (r_anal_function_has_address_linked_signature_current (fcn),
		"prepared poison blocks the exact address-linked signature");
	RAnalFunctionSnapshot *poisoned = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (poisoned, "collect poisoned address-link snapshot");
	mu_assert_false (poisoned->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"poisoned parser link cannot certify an exact interface");
	r_anal_function_snapshot_free (poisoned);
	mu_assert_true (r_anal_function_type_link_set_owned (anal, fcn->name, fcn->addr),
		"owned setter accepts the identical prepared link");
	mu_assert_true (r_anal_dwarf_function_link_poisoned_matches (
		anal, fcn->addr, fcn->name), "owned setter preserves prepared poison");
	mu_assert_true (r_anal_dwarf_function_link_publish_owned (
		anal, fcn->addr, fcn->name), "publish complete parser-owned link");
	mu_assert_true (r_anal_function_has_address_linked_signature_current (fcn),
		"owned publication restores exact address-link authority");
	RAnalFunctionSnapshot *published = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (published, "collect published address-link snapshot");
	mu_assert_true (published->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"published parser link restores exact-interface capability");
	r_anal_function_snapshot_free (published);
	mu_assert_true (snapshot_test_publish_frame_pointer (anal, fcn, "rbp"),
		"publish parser-owned full-width frame pointer");
	RAnalFunctionSnapshot *frame_snapshot =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (frame_snapshot, "collect slotless exact frame-pointer snapshot");
	mu_assert_true (frame_snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FRAME_POINTER_STORAGE,
		"slotless exact interface carries parser-owned frame pointer");
	RAnalSnapshotRegisterStorageView frame_pointer = {0};
	mu_assert_true (r_anal_function_snapshot_interface_frame_pointer_storage (
		frame_snapshot, &frame_pointer), "copy exact frame-pointer storage");
	RRegItem *rbp = r_reg_get (anal->reg, "rbp", -1);
	mu_assert_notnull (rbp, "resolve exact frame-pointer register");
	mu_assert_eq (frame_pointer.offset, (ut64)(rbp->offset / 8),
		"frame pointer uses canonical byte coordinates");
	mu_assert_eq (frame_pointer.size, 8, "frame pointer is address width");
	r_unref (rbp);
	char frame_pointer_name[16] = {0};
	mu_assert_true (r_anal_function_snapshot_interface_storage_name (
		frame_snapshot, R_ANAL_SNAPSHOT_INTERFACE_STORAGE_FRAME_POINTER,
		frame_pointer_name, sizeof (frame_pointer_name)),
		"copy exact frame-pointer name");
	mu_assert_streq (frame_pointer_name, "rbp", "frame pointer name is owned");
	const ut64 frame_pointer_revision = frame_snapshot->revision_identity;

	mu_assert_true (snapshot_test_publish_frame_pointer (anal, fcn, NULL),
		"publish authoritative absence of a frame-pointer proof");
	RAnalFunctionSnapshot *no_frame_snapshot =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (no_frame_snapshot, "collect snapshot without frame proof");
	mu_assert_false (no_frame_snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FRAME_POINTER_STORAGE,
		"absent proof cannot carry frame-pointer authority");
	frame_pointer.offset = 99;
	frame_pointer.size = 99;
	mu_assert_false (r_anal_function_snapshot_interface_frame_pointer_storage (
		no_frame_snapshot, &frame_pointer), "absent frame-pointer accessor refuses");
	mu_assert_eq (frame_pointer.offset, 0, "failed frame accessor clears offset");
	mu_assert_eq (frame_pointer.size, 0, "failed frame accessor clears size");
	mu_assert_neq (no_frame_snapshot->revision_identity, frame_pointer_revision,
		"frame-pointer presence participates in snapshot identity");
	mu_assert_true (r_anal_function_snapshot_interface_frame_pointer_storage (
		frame_snapshot, &frame_pointer), "old snapshot retains frame-pointer proof");
	mu_assert_eq (frame_pointer.size, 8, "old frame-pointer snapshot is immutable");
	r_anal_function_snapshot_free (no_frame_snapshot);

	mu_assert_true (snapshot_test_publish_frame_pointer (anal, fcn, "rsp"),
		"publish structurally conflicting frame-pointer proof");
	RAnalFunctionSnapshot *conflicting_frame_snapshot =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (conflicting_frame_snapshot,
		"collect conflicting frame-pointer snapshot");
	mu_assert_false (conflicting_frame_snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FRAME_POINTER_STORAGE,
		"stack-pointer overlap cannot carry frame-pointer authority");
	r_anal_function_snapshot_free (conflicting_frame_snapshot);
	mu_assert_true (snapshot_test_publish_frame_pointer (anal, fcn, "rbp"),
		"restore parser-owned frame-pointer proof");
	r_anal_function_snapshot_free (frame_snapshot);
	mu_assert_true (r_anal_dwarf_function_link_mark_poisoned (
		anal, fcn->addr, fcn->name), "poison owned link before user replacement");
	mu_assert_true (r_anal_function_type_link_set (anal, fcn->name, fcn->addr),
		"ordinary identical setter accepts a user replacement");
	mu_assert_false (r_anal_dwarf_function_link_poisoned_matches (
		anal, fcn->addr, fcn->name), "ordinary identical setter clears private ownership");
	mu_assert_true (r_anal_function_has_address_linked_signature_current (fcn),
		"same-valued foreign replacement remains authoritative");
	RAnalFunctionSnapshot *rsp_snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rsp_snapshot, "collect full-width RSP snapshot");
	mu_assert_true (rsp_snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"full-width RSP carries stack-pointer authority");
	mu_assert_true (rsp_snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"slotless exact interface accepts full-width RSP");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rbx"),
		"point SP role at a distinct full-width register");
	RAnalFunctionSnapshot *rbx_snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rbx_snapshot, "collect full-width RBX snapshot");
	mu_assert_true (rbx_snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"full-width RBX carries stack-pointer authority");
	mu_assert_true (rbx_snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"slotless exact interface accepts full-width RBX");
	mu_assert_neq (rbx_snapshot->function_interface.stack_pointer_storage.offset,
		rsp_snapshot->function_interface.stack_pointer_storage.offset,
		"alternate stack-pointer role changes canonical byte coordinates");
	mu_assert_neq (rbx_snapshot->revision_identity, rsp_snapshot->revision_identity,
		"full-width stack-pointer storage participates in snapshot identity");
	r_anal_function_snapshot_free (rbx_snapshot);
	r_anal_function_snapshot_free (rsp_snapshot);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rsp"),
		"restore canonical SP role");
	const int rdi = reg_index (anal, "rdi");
	mu_assert ("rdi register index must resolve", rdi >= 0);
	RAnalVar *home_source = r_anal_function_set_var (
		fcn, rdi, R_ANAL_VAR_KIND_REG, "int64_t", 8, true, "value");
	RAnalVar *bp_slot = r_anal_function_set_var (
		fcn, -8, R_ANAL_VAR_KIND_BPV, "int32_t", 4, false, "exact_bp_slot");
	RAnalVar *sp_slot = r_anal_function_set_var (
		fcn, -8, R_ANAL_VAR_KIND_SPV, "int32_t", 4, false, "exact_sp_slot");
	mu_assert_notnull (home_source, "create exact parameter-home source");
	mu_assert_notnull (bp_slot, "create exact BP stack slot");
	mu_assert_notnull (sp_slot, "create exact SP stack slot");
	r_anal_var_set_access (anal, home_source, "rdi", 0x7010, R_PERM_R, 0);
	r_anal_var_set_access (anal, bp_slot, "rbp", 0x7010, R_PERM_W, -8);

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect exact function snapshot");
	mu_assert_true (snapshot->function_interface.complete, "exact register interface is complete");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"exact interface capability is present");
	mu_assert_true (snapshot->function_interface.stack_slot_roles_complete,
		"local and canonical parameter-home roles are exact");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES,
		"exact stack-slot-role capability is present");
	mu_assert_streq (snapshot->function_interface.calling_convention, "exactcc", "exact calling convention");
	mu_assert_eq (snapshot->function_interface.num_parameters, 1, "one exact parameter");
	mu_assert_eq (snapshot->function_interface.parameters[0].index, 0, "exact parameter order");
	mu_assert_streq (snapshot->function_interface.parameters[0].name, "value",
		"exact parameter presentation name is owned");
	mu_assert_streq (snapshot->function_interface.parameters[0].storage.name, "rdi", "exact parameter register");
	RAnalSnapshotParameterView parameter_view = {0};
	mu_assert_true (r_anal_function_snapshot_parameter_view (
		snapshot, 0, &parameter_view), "copy exact parameter view");
	mu_assert_eq (parameter_view.name_length, strlen ("value"),
		"parameter view reports the exact owned presentation length");
	char parameter_name[16] = {0};
	mu_assert_true (r_anal_function_snapshot_parameter_name (
		snapshot, 0, parameter_name, sizeof (parameter_name)),
		"copy exact parameter presentation name");
	mu_assert_streq (parameter_name, "value", "parameter presentation copy is exact");
	RRegItem *rdi_item = r_reg_get (anal->reg, "rdi", -1);
	mu_assert_notnull (rdi_item, "resolve exact parameter carrier");
	mu_assert_eq (snapshot->function_interface.parameters[0].storage.offset,
		(ut64)(rdi_item->offset / 8),
		"parameter storage uses canonical byte coordinates");
	mu_assert_eq (snapshot->function_interface.return_kind, R_ANAL_SNAPSHOT_RETURN_REGISTER, "register return kind");
	mu_assert_streq (snapshot->function_interface.return_storage.name, "rax", "exact return register");
	RRegItem *rax_item = r_reg_get (anal->reg, "rax", -1);
	mu_assert_notnull (rax_item, "resolve exact return carrier");
	mu_assert_eq (snapshot->function_interface.return_storage.offset,
		(ut64)(rax_item->offset / 8),
		"return storage uses canonical byte coordinates");
	r_unref (rax_item);
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"exact x86 snapshot carries the typed return-address register");
	mu_assert_streq (snapshot->function_interface.return_address_storage.name, "rip",
		"stack-return target is carried in the typed PC register");
	RRegItem *rip = r_reg_get (anal->reg, "rip", -1);
	mu_assert_notnull (rip, "resolve typed PC carrier");
	mu_assert_eq (snapshot->function_interface.return_address_storage.offset,
		(ut64)(rip->offset / 8),
		"x86 return-address carrier uses canonical byte coordinates");
	r_unref (rip);
	mu_assert_eq (snapshot->function_interface.return_address_storage.size, 8,
		"x86 return-address carrier is full width");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"exact x86 snapshot carries the typed stack pointer");
	mu_assert_streq (snapshot->function_interface.stack_pointer_storage.name, "rsp",
		"typed SP role carries the full-width stack pointer");
	RRegItem *rsp = r_reg_get (anal->reg, "rsp", -1);
	mu_assert_notnull (rsp, "resolve typed SP carrier");
	mu_assert_eq (snapshot->function_interface.stack_pointer_storage.offset,
		(ut64)(rsp->offset / 8),
		"x86 stack-pointer carrier uses canonical byte coordinates");
	r_unref (rsp);
	mu_assert_eq (snapshot->function_interface.stack_pointer_storage.size, 8,
		"x86 stack-pointer carrier is full width");
	mu_assert_true (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM,
		"exact x86 snapshot carries its stack-return mechanism");
	RAnalSnapshotReturnMechanismView return_mechanism;
	mu_assert_true (r_anal_function_snapshot_interface_return_mechanism (
		snapshot, &return_mechanism), "copy exact stack-return mechanism");
	mu_assert_eq (return_mechanism.kind,
		R_ANAL_SNAPSHOT_RETURN_MECHANISM_STACK, "stack-return mechanism kind");
	mu_assert_eq (return_mechanism.entry_sp_offset, 0, "return slot starts at entry SP");
	mu_assert_eq (return_mechanism.slot_size, 8, "return slot is address-sized");
	mu_assert_eq (return_mechanism.exit_sp_delta, 8, "stack return consumes one slot");
	mu_assert_true (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT,
		"exact x86 snapshot carries its source-owned stack allocation contract");
	RAnalSnapshotStackAllocationContractView stack_allocation_contract;
	mu_assert_true (r_anal_function_snapshot_interface_stack_allocation_contract (
		snapshot, &stack_allocation_contract), "copy exact stack allocation contract");
	mu_assert_eq (stack_allocation_contract.growth,
		R_ANAL_SNAPSHOT_STACK_GROWTH_LOWER, "exact CC owns only lower-address reservations");
	mu_assert_eq (stack_allocation_contract.implicit_active_sp_bytes, 128,
		"exact CC seals its implicit active-SP red zone");
	const ut64 stack_allocation_revision = snapshot->revision_identity;
	sdb_set (anal->sdb_cc, "cc.exactcc.redzone", "64", 0);
	RAnalFunctionSnapshot *changed_red_zone =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (changed_red_zone, "collect changed red-zone contract");
	mu_assert_true (r_anal_function_snapshot_interface_stack_allocation_contract (
		changed_red_zone, &stack_allocation_contract),
		"changed red zone remains exact allocation authority");
	mu_assert_eq (stack_allocation_contract.growth,
		R_ANAL_SNAPSHOT_STACK_GROWTH_LOWER, "changed red zone preserves growth direction");
	mu_assert_eq (stack_allocation_contract.implicit_active_sp_bytes, 64,
		"changed red zone is sealed exactly");
	mu_assert_neq (changed_red_zone->revision_identity,
		stack_allocation_revision, "red-zone bytes participate in snapshot identity");
	r_anal_function_snapshot_free (changed_red_zone);
	const char *malformed_red_zones[] = { "junk", "-1", "4294967296" };
	size_t malformed_red_zone_index;
	for (malformed_red_zone_index = 0;
		malformed_red_zone_index < R_ARRAY_SIZE (malformed_red_zones);
		malformed_red_zone_index++) {
		sdb_set (anal->sdb_cc, "cc.exactcc.redzone",
			malformed_red_zones[malformed_red_zone_index], 0);
		RAnalFunctionSnapshot *malformed_red_zone =
			r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
		mu_assert_notnull (malformed_red_zone, "collect malformed red-zone contract");
		mu_assert_false (malformed_red_zone->capabilities
			& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT,
			"malformed red zone disables exact stack-allocation authority");
		stack_allocation_contract.growth = R_ANAL_SNAPSHOT_STACK_GROWTH_HIGHER;
		stack_allocation_contract.implicit_active_sp_bytes = 1;
		mu_assert_false (r_anal_function_snapshot_interface_stack_allocation_contract (
			malformed_red_zone, &stack_allocation_contract),
			"malformed red-zone accessor refuses");
		mu_assert_eq (stack_allocation_contract.growth,
			R_ANAL_SNAPSHOT_STACK_GROWTH_NONE,
			"refused red-zone accessor clears growth");
		mu_assert_eq (stack_allocation_contract.implicit_active_sp_bytes, 0,
			"refused red-zone accessor clears implicit active-SP bytes");
		r_anal_function_snapshot_free (malformed_red_zone);
	}
	sdb_unset (anal->sdb_cc, "cc.exactcc.redzone", 0);
	RAnalFunctionSnapshot *absent_red_zone =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (absent_red_zone, "collect allocation contract without red zone");
	mu_assert_true (absent_red_zone->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT,
		"absent red zone preserves exact stack-allocation authority");
	mu_assert_true (r_anal_function_snapshot_interface_stack_allocation_contract (
		absent_red_zone, &stack_allocation_contract),
		"allocation accessor accepts an absent red zone");
	mu_assert_eq (stack_allocation_contract.growth,
		R_ANAL_SNAPSHOT_STACK_GROWTH_LOWER,
		"absent red zone does not disable allocation growth");
	mu_assert_eq (stack_allocation_contract.implicit_active_sp_bytes, 0,
		"absent red zone seals exact zero implicit bytes");
	mu_assert_neq (absent_red_zone->revision_identity,
		stack_allocation_revision, "red-zone absence participates in snapshot identity");
	r_anal_function_snapshot_free (absent_red_zone);
	sdb_set (anal->sdb_cc, "cc.exactcc.redzone", "128", 0);
	sdb_set (anal->sdb_cc, "cc.exactcc.stackalloc", "down", 0);
	RAnalFunctionSnapshot *malformed_stack_allocation =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (malformed_stack_allocation, "collect malformed stack allocation contract");
	mu_assert_false (malformed_stack_allocation->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT,
		"unknown growth spelling carries no allocation authority");
	stack_allocation_contract.growth = R_ANAL_SNAPSHOT_STACK_GROWTH_HIGHER;
	mu_assert_false (r_anal_function_snapshot_interface_stack_allocation_contract (
		malformed_stack_allocation, &stack_allocation_contract),
		"malformed allocation accessor refuses");
	mu_assert_eq (stack_allocation_contract.growth,
		R_ANAL_SNAPSHOT_STACK_GROWTH_NONE, "refused accessor clears its scalar view");
	mu_assert_neq (malformed_stack_allocation->revision_identity,
		stack_allocation_revision, "malformed allocation changes snapshot identity");
	r_anal_function_snapshot_free (malformed_stack_allocation);
	sdb_set (anal->sdb_cc, "cc.exactcc.stackalloc", "higher", 0);
	RAnalFunctionSnapshot *higher_stack_allocation =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (higher_stack_allocation, "collect higher-address stack allocation contract");
	mu_assert_true (r_anal_function_snapshot_interface_stack_allocation_contract (
		higher_stack_allocation, &stack_allocation_contract),
		"higher-address contract remains explicit authority");
	mu_assert_eq (stack_allocation_contract.growth,
		R_ANAL_SNAPSHOT_STACK_GROWTH_HIGHER, "higher-address contract preserves direction");
	mu_assert_neq (higher_stack_allocation->revision_identity,
		stack_allocation_revision, "allocation direction participates in snapshot identity");
	r_anal_function_snapshot_free (higher_stack_allocation);
	sdb_unset (anal->sdb_cc, "cc.exactcc.stackalloc", 0);
	RAnalFunctionSnapshot *missing_stack_allocation =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (missing_stack_allocation, "collect missing stack allocation contract");
	mu_assert_false (missing_stack_allocation->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT,
		"missing source contract carries no allocation authority");
	r_anal_function_snapshot_free (missing_stack_allocation);
	sdb_set (anal->sdb_cc, "cc.exactcc.stackalloc", "lower", 0);
	ut64 return_mechanism_revision = snapshot->revision_identity;
	sdb_set (anal->sdb_cc, "cc.exactcc.retmech", "stack:8:8:16", 0);
	RAnalFunctionSnapshot *noncanonical_return_mechanism =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (noncanonical_return_mechanism, "collect noncanonical return mechanism");
	mu_assert_false (noncanonical_return_mechanism->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM,
		"noncanonical return-slot geometry carries no authority");
	mu_assert_neq (noncanonical_return_mechanism->revision_identity,
		return_mechanism_revision, "refused return mechanism changes snapshot identity");
	mu_assert_true (r_anal_function_snapshot_interface_return_mechanism (
		snapshot, &return_mechanism), "old snapshot retains return mechanism");
	mu_assert_eq (return_mechanism.entry_sp_offset, 0, "old snapshot remains immutable");
	r_anal_function_snapshot_free (noncanonical_return_mechanism);
	sdb_set (anal->sdb_cc, "cc.exactcc.retmech", "stack:0:0:8", 0);
	RAnalFunctionSnapshot *malformed_return_mechanism =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (malformed_return_mechanism, "collect malformed return mechanism");
	mu_assert_false (malformed_return_mechanism->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM,
		"malformed return mechanism carries no authority");
	return_mechanism.kind = R_ANAL_SNAPSHOT_RETURN_MECHANISM_STACK;
	return_mechanism.slot_size = 99;
	mu_assert_false (r_anal_function_snapshot_interface_return_mechanism (
		malformed_return_mechanism, &return_mechanism),
		"accessor rejects malformed return mechanism");
	mu_assert_eq (return_mechanism.kind, R_ANAL_SNAPSHOT_RETURN_MECHANISM_NONE,
		"failed accessor clears its scalar view");
	mu_assert_eq (return_mechanism.slot_size, 0, "failed accessor clears return slot size");
	r_anal_function_snapshot_free (malformed_return_mechanism);
	sdb_unset (anal->sdb_cc, "cc.exactcc.retmech", 0);
	RAnalFunctionSnapshot *missing_return_mechanism =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (missing_return_mechanism, "collect missing return mechanism");
	mu_assert_false (missing_return_mechanism->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM,
		"missing return mechanism carries no authority");
	r_anal_function_snapshot_free (missing_return_mechanism);
	sdb_set (anal->sdb_cc, "cc.exactcc.retmech", "stack:0:8:8", 0);
	RAnalVar *return_slot_overlap = r_anal_function_set_var (
		fcn, 0, R_ANAL_VAR_KIND_SPV, "int32_t", 4, false, "return_slot_overlap");
	mu_assert_notnull (return_slot_overlap, "create SP local overlapping the return slot");
	RAnalFunctionSnapshot *overlapping_return_mechanism =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (overlapping_return_mechanism, "collect overlapping return slot");
	mu_assert_true (overlapping_return_mechanism->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"overlap refusal does not erase the independently exact interface");
	mu_assert_false (overlapping_return_mechanism->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM,
		"declared SP local overlapping the return slot carries no mechanism authority");
	r_anal_function_snapshot_free (overlapping_return_mechanism);
	mu_assert_true (r_anal_var_delete (anal, return_slot_overlap),
		"remove the overlapping return-slot local");
	ut64 stack_pointer_revision = snapshot->revision_identity;
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "sp"),
		"point SP role at a narrow register");
	RAnalFunctionSnapshot *narrow_stack_pointer =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (narrow_stack_pointer, "collect narrow stack-pointer snapshot");
	mu_assert_false (narrow_stack_pointer->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"narrow SP register cannot carry stack-pointer authority");
	mu_assert_false (narrow_stack_pointer->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"narrow SP register cannot preserve exact interface authority");
	mu_assert_neq (narrow_stack_pointer->revision_identity, stack_pointer_revision,
		"stack-pointer carrier changes snapshot revision identity");
	r_anal_function_snapshot_free (narrow_stack_pointer);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "not_a_register"),
		"make the typed SP role unresolvable");
	RAnalFunctionSnapshot *missing_stack_pointer =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (missing_stack_pointer, "collect missing stack-pointer snapshot");
	mu_assert_false (missing_stack_pointer->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"no literal register-name fallback supplies stack-pointer authority");
	r_anal_function_snapshot_free (missing_stack_pointer);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rdi"),
		"point SP role at the parameter register");
	RAnalFunctionSnapshot *stack_parameter_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (stack_parameter_collision, "collect SP-parameter collision snapshot");
	mu_assert_false (stack_parameter_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"parameter collision rejects stack-pointer authority");
	mu_assert_false (stack_parameter_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"parameter collision rejects exact interface authority");
	r_anal_function_snapshot_free (stack_parameter_collision);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rax"),
		"point SP role at the return-value register");
	RAnalFunctionSnapshot *stack_return_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (stack_return_collision, "collect SP-return collision snapshot");
	mu_assert_false (stack_return_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"return-value collision rejects stack-pointer authority");
	mu_assert_false (stack_return_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"return-value collision rejects exact interface authority");
	r_anal_function_snapshot_free (stack_return_collision);
	free (home_source->regname);
	home_source->regname = strdup ("r12");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "r12"),
		"point SP role at a distinct parameter-home register");
	RAnalFunctionSnapshot *stack_home_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (stack_home_collision, "collect SP-home collision snapshot");
	mu_assert_false (stack_home_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"parameter-home collision rejects stack-pointer authority");
	mu_assert_false (stack_home_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"parameter-home collision rejects exact interface authority");
	r_anal_function_snapshot_free (stack_home_collision);
	free (home_source->regname);
	home_source->regname = strdup ("rdi");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rip"),
		"point SP role at the return-address register");
	RAnalFunctionSnapshot *stack_return_address_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (stack_return_address_collision,
		"collect SP-return-address collision snapshot");
	mu_assert_false (stack_return_address_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"return-address collision rejects stack-pointer authority");
	mu_assert_false (stack_return_address_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"SP collision simultaneously clears return-address authority");
	r_anal_function_snapshot_free (stack_return_address_collision);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rbp"),
		"point SP role at the BP stack-slot base");
	RAnalFunctionSnapshot *stack_bp_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (stack_bp_collision, "collect SP-BP collision snapshot");
	mu_assert_false (stack_bp_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"BP-base collision rejects stack-pointer authority");
	r_anal_function_snapshot_free (stack_bp_collision);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "rsp"),
		"restore typed SP role");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "edi"),
		"point PC role at a narrow register");
	RAnalFunctionSnapshot *narrow_return_address =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (narrow_return_address, "collect narrow return-address snapshot");
	mu_assert_false (narrow_return_address->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"narrow PC register cannot carry return-address authority");
	mu_assert_false (narrow_return_address->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"narrow PC register cannot preserve exact interface authority");
	r_anal_function_snapshot_free (narrow_return_address);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "rdi"),
		"point PC role at the parameter register");
	RAnalFunctionSnapshot *parameter_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (parameter_collision, "collect parameter-collision snapshot");
	mu_assert_false (parameter_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"parameter collision rejects return-address authority");
	mu_assert_false (parameter_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"parameter collision rejects exact interface authority");
	r_anal_function_snapshot_free (parameter_collision);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "rax"),
		"point PC role at the return register");
	RAnalFunctionSnapshot *return_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (return_collision, "collect return-collision snapshot");
	mu_assert_false (return_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"return-value collision rejects return-address authority");
	mu_assert_false (return_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"return-value collision rejects exact interface authority");
	r_anal_function_snapshot_free (return_collision);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "rbp"),
		"point PC role at the BP stack-slot base");
	RAnalFunctionSnapshot *bp_base_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (bp_base_collision, "collect BP-base-collision snapshot");
	mu_assert_false (bp_base_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"BP stack-slot base collision rejects return-address authority");
	mu_assert_null (bp_base_collision->function_interface.return_address_storage.name,
		"BP stack-slot base collision clears the carrier");
	mu_assert_false (bp_base_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"BP stack-slot base collision rejects exact interface authority");
	r_anal_function_snapshot_free (bp_base_collision);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "rsp"),
		"point PC role at the SP stack-slot base");
	RAnalFunctionSnapshot *sp_base_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (sp_base_collision, "collect SP-base-collision snapshot");
	mu_assert_false (sp_base_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"SP stack-slot base collision rejects return-address authority");
	mu_assert_null (sp_base_collision->function_interface.return_address_storage.name,
		"SP stack-slot base collision clears the carrier");
	mu_assert_false (sp_base_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"SP stack-slot base collision rejects exact interface authority");
	r_anal_function_snapshot_free (sp_base_collision);
	free (home_source->regname);
	home_source->regname = strdup ("r12");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "r12"),
		"point PC role at a distinct parameter-home register");
	RAnalFunctionSnapshot *home_collision =
		r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (home_collision, "collect parameter-home-collision snapshot");
	mu_assert_false (home_collision->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"distinct parameter-home collision rejects return-address authority");
	mu_assert_null (home_collision->function_interface.return_address_storage.name,
		"distinct parameter-home collision clears the carrier");
	r_anal_function_snapshot_free (home_collision);
	free (home_source->regname);
	home_source->regname = strdup ("rdi");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, "rip"),
		"restore typed PC role");
	RAnalFcnSlot *bp_resource = find_stack_slot (&snapshot->context, "exact_bp_slot");
	RAnalFcnSlot *sp_resource = find_stack_slot (&snapshot->context, "exact_sp_slot");
	mu_assert_notnull (bp_resource, "snapshot owns exact BP resource");
	mu_assert_notnull (sp_resource, "snapshot owns exact SP resource");
	RAnalFunctionSnapshotView public_snapshot;
	mu_assert_true (r_anal_function_snapshot_view (snapshot, &public_snapshot),
		"open public exact snapshot view");
	mu_assert_eq (public_snapshot.num_stack_slots,
		(size_t)r_list_length (snapshot->context.fcn_slots),
		"public view reports every owned stack slot");
	bool saw_public_bp_slot = false;
	size_t slot_index;
	for (slot_index = 0; slot_index < public_snapshot.num_stack_slots; slot_index++) {
		RAnalSnapshotStackSlotView slot_view;
		char slot_name[64];
		char base_name[64];
		mu_assert_true (r_anal_function_snapshot_stack_slot_view (
			snapshot, slot_index, &slot_view), "copy public stack-slot view");
		mu_assert_true (r_anal_function_snapshot_stack_slot_string (
			snapshot, slot_index, R_ANAL_SNAPSHOT_STACK_SLOT_STRING_NAME,
			slot_name, sizeof (slot_name)), "copy public stack-slot name");
		mu_assert_true (r_anal_function_snapshot_stack_slot_string (
			snapshot, slot_index, R_ANAL_SNAPSHOT_STACK_SLOT_STRING_BASE_NAME,
			base_name, sizeof (base_name)), "copy public stack-slot base name");
		if (!strcmp (slot_name, "exact_bp_slot")) {
			saw_public_bp_slot = slot_view.base == R_ANAL_FCN_BASE_BP
				&& slot_view.base_offset == bp_resource->base_offset
				&& slot_view.base_size == bp_resource->base_size
				&& slot_view.offset == bp_resource->offset
				&& slot_view.size == bp_resource->size
				&& slot_view.offset_valid && slot_view.role == bp_resource->role
				&& slot_view.arg_index == bp_resource->arg_index
				&& slot_view.home_reg_offset == bp_resource->home_reg_offset
				&& slot_view.home_reg_size == bp_resource->home_reg_size
				&& !strcmp (base_name, "rbp");
		}
	}
	mu_assert_true (saw_public_bp_slot,
		"public stack-slot accessors preserve exact typed coordinates");
	RAnalSnapshotStackSlotView invalid_slot;
	mu_assert_false (r_anal_function_snapshot_stack_slot_view (
		snapshot, public_snapshot.num_stack_slots, &invalid_slot),
		"public stack-slot view rejects out-of-range index");
	mu_assert_eq (bp_resource->base, R_ANAL_FCN_BASE_BP, "exact BP resource base");
	mu_assert_streq (bp_resource->base_name, "rbp", "exact BP resource register");
	mu_assert_eq (bp_resource->base_size, 8, "exact BP resource register size");
	RRegItem *rbp_item = r_reg_get (anal->reg, "rbp", -1);
	mu_assert_notnull (rbp_item, "resolve exact BP slot base");
	mu_assert_eq (bp_resource->base_offset, (ut64)(rbp_item->offset / 8),
		"BP slot base uses canonical byte coordinates");
	r_unref (rbp_item);
	mu_assert_eq (bp_resource->offset, -8, "exact BP resource offset");
	mu_assert_eq (bp_resource->size, 4, "exact BP resource size");
	mu_assert_true (bp_resource->offset_valid, "exact BP resource offset is valid");
	mu_assert_eq (bp_resource->role, R_ANAL_FCN_SLOT_HOME,
		"exact BP resource is a parameter home");
	mu_assert_eq (bp_resource->arg_index, 0,
		"exact parameter home identifies its interface parameter");
	mu_assert_eq (bp_resource->home_reg_offset,
		snapshot->function_interface.parameters[0].storage.offset,
		"exact parameter home has canonical register offset");
	mu_assert_eq (bp_resource->home_reg_offset, (ut64)(rdi_item->offset / 8),
		"parameter home uses canonical byte coordinates");
	r_unref (rdi_item);
	mu_assert_eq (bp_resource->home_reg_size,
		snapshot->function_interface.parameters[0].storage.size,
		"exact parameter home has canonical register size");
	mu_assert_eq (sp_resource->role, R_ANAL_FCN_SLOT_LOCAL,
		"exact SP resource remains a local");
	mu_assert_eq (sp_resource->arg_index, -1,
		"local stack resource carries no parameter authority");
	RRegItem *rsp_item = r_reg_get (anal->reg, "rsp", -1);
	mu_assert_notnull (rsp_item, "resolve exact SP slot base");
	mu_assert_eq (sp_resource->base_offset, (ut64)(rsp_item->offset / 8),
		"SP slot base uses canonical byte coordinates");
	r_unref (rsp_item);
	mu_assert_true (snapshot->function_interface.stack_resources_complete,
		"different exact bases may use the same relative range");
	ut64 exact_revision = snapshot->revision_identity;
	free (home_source->regname);
	home_source->regname = strdup ("edi");
	RAnalFunctionSnapshot *mismatched_home = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (mismatched_home, "collect mismatched parameter-home snapshot");
	mu_assert_false (mismatched_home->function_interface.stack_slot_roles_complete,
		"subregister storage cannot prove a full-register parameter home");
	mu_assert_false (mismatched_home->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES,
		"mismatched home storage omits exact-role capability");
	mu_assert_neq (mismatched_home->revision_identity, exact_revision,
		"canonical home payload changes snapshot revision identity");
	r_anal_function_snapshot_free (mismatched_home);
	free (home_source->regname);
	home_source->regname = strdup ("rdi");
	r_anal_var_set_type (anal, bp_slot, "int64_t");
	mu_assert_eq (bp_resource->size, 4, "owned snapshot resource remains immutable after live type mutation");
	RAnalFunctionSnapshot *resized = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (resized, "collect resized exact resource snapshot");
	RAnalFcnSlot *resized_resource = find_stack_slot (&resized->context, "exact_bp_slot");
	mu_assert_notnull (resized_resource, "resized exact resource remains owned");
	mu_assert_eq (resized_resource->size, 8, "new snapshot observes exact resource size change");
	mu_assert_neq (resized->revision_identity, exact_revision, "exact resource mutation changes revision");
	r_anal_function_snapshot_free (resized);

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_BP, "r14"),
		"use valid non-whitelisted full-width BP register");
	RAnalFunctionSnapshot *nonstandard_base = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (nonstandard_base, "collect non-whitelisted exact base snapshot");
	RAnalFcnSlot *nonstandard_resource = find_stack_slot (&nonstandard_base->context, "exact_bp_slot");
	mu_assert_notnull (nonstandard_resource, "non-whitelisted base resource remains exact");
	mu_assert_eq (nonstandard_resource->base, R_ANAL_FCN_BASE_BP,
		"semantic BP role is independent of register spelling");
	mu_assert_streq (nonstandard_resource->base_name, "r14",
		"snapshot transports the actual full-width base register");
	mu_assert_eq (nonstandard_resource->base_size, 8,
		"non-whitelisted base keeps its full register width");
	mu_assert_true (nonstandard_base->function_interface.stack_resources_complete,
		"valid non-whitelisted base preserves exact stack resources");
	r_anal_function_snapshot_free (nonstandard_base);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_BP, "rbp"),
		"restore typed BP role");
	mu_assert_true (r_anal_var_delete (anal, sp_slot),
		"remove the SP-relative slot for BP-only coverage");
	RAnalFunctionSnapshot *bp_only = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (bp_only, "collect BP-only exact snapshot");
	mu_assert_null (find_stack_slot (&bp_only->context, "exact_sp_slot"),
		"BP-only snapshot contains no SP-relative slot");
	mu_assert_true (bp_only->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"BP-only snapshot carries typed SP independently of slots");
	mu_assert_true (bp_only->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"BP-only frame preserves exact interface authority");
	mu_assert_false (bp_only->function_interface.noreturn,
		"control still comes back before the noreturn mutation");
	r_anal_function_snapshot_free (bp_only);
	r_anal_function_snapshot_free (snapshot);

	signature.noreturn = true;
	parameters = r_list_new ();
	mu_assert_notnull (parameters, "recreate exact parameter list");
	mu_assert_true (r_list_append (parameters, &parameter), "reappend exact parameter");
	signature.params = parameters;
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature), "apply noreturn signature");
	r_list_free (parameters);
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect noreturn snapshot");
	// noreturn says control does not come back, which is not a statement about
	// whether the parameter and return storage were recovered. It is recorded
	// as a fact of the interface, and it withholds nothing: the carriers below
	// were all resolved without reference to whether the function returns.
	mu_assert_true (snapshot->function_interface.noreturn,
		"the snapshot records that control does not come back");
	mu_assert_true (snapshot->function_interface.complete,
		"noreturn does not withhold the recovered interface");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"noreturn snapshot keeps exact interface capability");
	mu_assert_eq (snapshot->function_interface.num_parameters, 1,
		"noreturn snapshot keeps the parameter it recovered");
	mu_assert_streq (snapshot->function_interface.parameters[0].name, "value",
		"noreturn snapshot keeps the parameter name a consumer would show");
	mu_assert_streq (snapshot->function_interface.parameters[0].storage.name, "rdi",
		"noreturn snapshot keeps the parameter carrier");
	mu_assert_eq (snapshot->function_interface.return_kind,
		R_ANAL_SNAPSHOT_RETURN_REGISTER,
		"noreturn snapshot keeps the result carrier kind");
	mu_assert_streq (snapshot->function_interface.return_storage.name, "rax",
		"noreturn snapshot keeps the result carrier");
	mu_assert_neq (snapshot->revision_identity, exact_revision, "interface mutation changes revision");
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_prefers_link_register_return_address(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create ARM64 return-address snapshot analysis");
	mu_assert_true (r_anal_use (anal, "arm"), "load ARM analysis profile");
	r_anal_set_bits (anal, 64);
	RAnalFunction *fcn = r_anal_create_function (
		anal, "arm64_return_address_snapshot", 0x7100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create ARM64 return-address snapshot function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back ARM64 snapshot with exact bytes");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_RA, "x29"),
		"seed typed RA fallback distinct from LR and PC");

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect ARM64 return-address snapshot");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"ARM64 snapshot carries the typed return-address register");
	mu_assert_streq (snapshot->function_interface.return_address_storage.name, "x30",
		"typed LR alias wins over the PC alias");
	mu_assert_eq (snapshot->function_interface.return_address_storage.size, 8,
		"ARM64 link-register carrier is full width");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"ARM64 snapshot carries SP independently of stack slots");
	mu_assert_streq (snapshot->function_interface.stack_pointer_storage.name, "sp",
		"ARM64 typed SP role is carried without slot inference");
	mu_assert_eq (snapshot->function_interface.stack_pointer_storage.size, 8,
		"ARM64 stack-pointer carrier is full width");
	mu_assert_false (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM,
		"ARM64 profile without an exact mechanism carries no return authority");
	RAnalSnapshotReturnMechanismView return_mechanism;
	mu_assert_false (r_anal_function_snapshot_interface_return_mechanism (
		snapshot, &return_mechanism), "ARM64 absent mechanism is not exposed");
	r_anal_function_snapshot_free (snapshot);

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "wsp"),
		"make ARM64 SP role narrower than the function address");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect narrow ARM64 stack-pointer snapshot");
	mu_assert_false (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"narrow ARM64 SP cannot carry stack-pointer authority");
	r_anal_function_snapshot_free (snapshot);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, ""),
		"clear typed ARM64 SP alias");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect ARM64 snapshot without SP alias");
	mu_assert_false (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE,
		"literal SP name cannot replace missing typed role authority");
	r_anal_function_snapshot_free (snapshot);
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_SP, "sp"),
		"restore typed ARM64 SP role");

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_LR, "not_a_register"),
		"make higher-priority LR alias unresolvable");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect RA fallback snapshot");
	mu_assert_true (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"usable RA fallback carries return-address authority");
	mu_assert_streq (snapshot->function_interface.return_address_storage.name, "x29",
		"typed RA alias follows an unusable LR alias");
	r_anal_function_snapshot_free (snapshot);

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_LR, "w30"),
		"make higher-priority LR alias narrower than the function address");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect RA fallback from narrow LR snapshot");
	mu_assert_true (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"full-width RA fallback carries return-address authority");
	mu_assert_streq (snapshot->function_interface.return_address_storage.name, "x29",
		"full-width RA alias follows a narrow LR alias");
	r_anal_function_snapshot_free (snapshot);

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_LR, ""),
		"clear typed LR alias");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_RA, "not_a_register"),
		"make higher-priority RA alias unresolvable");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect PC fallback snapshot");
	mu_assert_true (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"usable PC fallback carries return-address authority");
	mu_assert_streq (snapshot->function_interface.return_address_storage.name, "pc",
		"typed PC alias follows unusable LR and RA aliases");
	r_anal_function_snapshot_free (snapshot);

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_PC, ""),
		"clear final typed PC alias");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect snapshot without a usable typed alias");
	mu_assert_false (snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE,
		"no literal name fallback supplies return-address authority");
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_falls_back_from_unusable_linked_cc(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create calling-convention fallback analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax amd64(rdi,rsi,rdx,rcx,r8,r9)"),
		"seed live target calling convention");
	mu_assert_true (r_anal_cc_set (anal, "rax cdecl(stack)"),
		"seed stack-only linked calling convention");
	mu_assert_true (r_anal_cc_set (anal, "rax usablecc(rdx)"),
		"seed usable conflicting calling convention");
	sdb_set (anal->sdb_cc, "cc.amd64.retmech", "stack:0:8:8", 0);
	sdb_set (anal->sdb_cc, "cc.cdecl.retmech", "stack:8:8:16", 0);

	sdb_set (anal->sdb_types, "linked_cdecl", "func", 0);
	sdb_set (anal->sdb_types, "func.linked_cdecl.ret", "int32_t", 0);
	sdb_set (anal->sdb_types, "func.linked_cdecl.args", "1", 0);
	sdb_set (anal->sdb_types, "func.linked_cdecl.arg.0", "int32_t,x", 0);
	sdb_set (anal->sdb_types, "func.linked_cdecl", "x", 0);
	sdb_set (anal->sdb_types, "func.linked_cdecl.cc", "cdecl", 0);
	RAnalFunction *fallback = r_anal_create_function (
		anal, "fallback_snapshot", 0x7200, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fallback, "create linked-CC fallback function");
	mu_assert_true (snapshot_test_ensure_block (anal, fallback, 1),
		"back fallback snapshot with exact bytes");
	fallback->callconv = r_str_constpool_get (&anal->constpool, "amd64");
	mu_assert_true (set_function_type_link (anal, "linked_cdecl", fallback->addr),
		"link stack-CC type by address");
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fallback, NULL);
	mu_assert_notnull (snapshot, "collect linked-CC fallback snapshot");
	mu_assert_true (snapshot->function_interface.complete,
		"live register CC completes an unusable linked stack interface");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"fallback snapshot certifies its exact interface");
	mu_assert_streq (snapshot->function_interface.calling_convention, "amd64",
		"physical carriers use the usable live target CC");
	RAnalSnapshotReturnMechanismView return_mechanism;
	mu_assert_true (r_anal_function_snapshot_interface_return_mechanism (
		snapshot, &return_mechanism), "fallback exposes selected live CC mechanism");
	mu_assert_eq (return_mechanism.entry_sp_offset, 0,
		"fallback mechanism comes from selected amd64 CC");
	mu_assert_eq (return_mechanism.exit_sp_delta, 8,
		"fallback ignores the unusable linked CC mechanism");
	mu_assert_eq (snapshot->function_interface.num_parameters, 1,
		"linked logical signature retains one parameter");
	mu_assert_streq (snapshot->function_interface.parameters[0].storage.name, "rdi",
		"live target CC supplies the parameter carrier");
	mu_assert_eq (snapshot->function_interface.parameters[0].carrier.kind,
		R_ANAL_SNAPSHOT_CARRIER_LOW_BITS, "linked int parameter retains its logical width");
	mu_assert_eq (snapshot->function_interface.parameters[0].carrier.size_bits, 32,
		"linked int parameter projects to 32 carrier bits");
	mu_assert_eq (snapshot->function_interface.return_kind,
		R_ANAL_SNAPSHOT_RETURN_REGISTER, "live target CC supplies a register return");
	mu_assert_streq (snapshot->function_interface.return_storage.name, "rax",
		"live target CC supplies the return carrier");
	mu_assert_eq (snapshot->function_interface.return_carrier.kind,
		R_ANAL_SNAPSHOT_CARRIER_LOW_BITS, "linked int return retains its logical width");
	mu_assert_eq (snapshot->function_interface.return_carrier.size_bits, 32,
		"linked int return projects to 32 carrier bits");
	r_anal_function_snapshot_free (snapshot);

	sdb_set (anal->sdb_types, "linked_usable", "func", 0);
	sdb_set (anal->sdb_types, "func.linked_usable.ret", "int64_t", 0);
	sdb_set (anal->sdb_types, "func.linked_usable.args", "1", 0);
	sdb_set (anal->sdb_types, "func.linked_usable.arg.0", "int64_t,x", 0);
	sdb_set (anal->sdb_types, "func.linked_usable", "x", 0);
	sdb_set (anal->sdb_types, "func.linked_usable.cc", "usablecc", 0);
	RAnalFunction *preserved = r_anal_create_function (
		anal, "preserved_snapshot", 0x7210, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (preserved, "create usable linked-CC function");
	mu_assert_true (snapshot_test_ensure_block (anal, preserved, 1),
		"back preserved snapshot with exact bytes");
	preserved->callconv = r_str_constpool_get (&anal->constpool, "amd64");
	mu_assert_true (set_function_type_link (anal, "linked_usable", preserved->addr),
		"link usable-CC type by address");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, preserved, NULL);
	mu_assert_notnull (snapshot, "collect usable linked-CC snapshot");
	mu_assert_true (snapshot->function_interface.complete,
		"usable linked calling convention remains exact");
	mu_assert_streq (snapshot->function_interface.calling_convention, "usablecc",
		"usable linked calling convention is not overridden");
	mu_assert_streq (snapshot->function_interface.parameters[0].storage.name, "rdx",
		"usable linked calling convention retains its parameter carrier");
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_seals_exact_reachable_type_graph(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create exact type-graph analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	r_anal_types_ensure_loaded (anal);
	sdb_reset (anal->sdb_types);
	mu_assert_true (r_anal_cc_set (anal, "rax exacttypes(rdi,rsi,rdx)"),
		"seed exact type-graph calling convention");
	RAnalBaseType *integer = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	integer->name = strdup ("int32_t");
	integer->type = strdup ("d");
	integer->size = 32;
	r_anal_save_base_type (anal, integer);
	r_anal_base_type_free (integer);
	mu_assert_true (save_snapshot_demo_struct_type (anal, 52, 0),
		"seed exact DemoStruct layout");

	RAnalFunction *fcn = r_anal_create_function (
		anal, "typed_graph_snapshot", 0x7800, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create exact type-graph function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back type-graph snapshot with exact bytes");
	RAnalFunctionParam parameters_data[] = {
		{ .name = "arr", .type = "DemoStruct *" },
		{ .name = "idx", .type = "int32_t" },
		{ .name = "v", .type = "int32_t" },
	};
	RList *parameters = r_list_new ();
	mu_assert_notnull (parameters, "create exact type-graph parameter list");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (parameters_data); i++) {
		mu_assert_true (r_list_append (parameters, &parameters_data[i]),
			"append exact type-graph parameter");
	}
	RAnalFunctionSignature signature = {
		.ret_type = "int32_t",
		.callconv = "exacttypes",
		.params = parameters,
	};
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature),
		"apply exact type-graph signature");
	mu_assert_true (set_function_type_link (anal, fcn->name, fcn->addr),
		"link exact type-graph signature by address");

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect exact reachable type graph");
	mu_assert_eq (snapshot->schema_version, R_ANAL_FUNCTION_SNAPSHOT_SCHEMA_VERSION,
		"exact graph uses the current snapshot schema");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"exact function-types capability is present");
	mu_assert_true (snapshot->type_graph.complete, "reachable type graph is complete");
	mu_assert_true (snapshot->function_interface.logical_types_complete,
		"parameter and return logical types are complete");
	mu_assert_eq (snapshot->type_graph.num_types, 3,
		"reachable graph contains one struct, scalar, and pointer node");
	mu_assert_eq (snapshot->type_graph.num_aggregates, 1,
		"reachable graph contains one aggregate layout");
	RAnalSnapshotParameter *arr = &snapshot->function_interface.parameters[0];
	RAnalSnapshotParameter *idx = &snapshot->function_interface.parameters[1];
	RAnalSnapshotParameter *value = &snapshot->function_interface.parameters[2];
	mu_assert ("array pointer logical type id is valid",
		arr->logical_type_id < snapshot->type_graph.num_types);
	mu_assert ("index logical type id is valid",
		idx->logical_type_id < snapshot->type_graph.num_types);
	mu_assert_eq (idx->logical_type_id, value->logical_type_id,
		"equal-width signed parameters share structural scalar identity");
	mu_assert_eq (idx->logical_type_id, snapshot->function_interface.return_type_id,
		"return shares the signed int32 logical identity");
	const RAnalSnapshotType *pointer =
		&snapshot->type_graph.types[arr->logical_type_id];
	const RAnalSnapshotType *scalar =
		&snapshot->type_graph.types[idx->logical_type_id];
	mu_assert_eq (pointer->kind, R_ANAL_SNAPSHOT_TYPE_POINTER,
		"array parameter is an exact pointer node");
	mu_assert_eq (pointer->size_bits, 64, "pointer width is sealed");
	mu_assert ("pointer target id is valid",
		pointer->target_type_id < snapshot->type_graph.num_types);
	const RAnalSnapshotType *structure =
		&snapshot->type_graph.types[pointer->target_type_id];
	mu_assert_eq (structure->kind, R_ANAL_SNAPSHOT_TYPE_STRUCT,
		"pointer target is an exact struct node");
	mu_assert_eq (structure->size_bits, 56 * 8, "DemoStruct stride is 56 bytes");
	mu_assert_eq (structure->align_bits, 32, "DemoStruct alignment is four bytes");
	mu_assert_eq (scalar->kind, R_ANAL_SNAPSHOT_TYPE_SIGNED_INTEGER,
		"member/index/value/return scalar is signed");
	mu_assert_eq (scalar->size_bits, 32, "logical integer width is 32 bits");
	mu_assert ("structure aggregate id is valid",
		structure->aggregate_id < snapshot->type_graph.num_aggregates);
	const RAnalSnapshotAggregateLayout *layout =
		&snapshot->type_graph.aggregates[structure->aggregate_id];
	mu_assert_true (layout->complete, "DemoStruct layout is complete");
	mu_assert_true (layout->c_layout_compatible,
		"DemoStruct obeys the sealed natural C layout contract");
	mu_assert_streq (layout->name, "DemoStruct", "aggregate label is preserved");
	mu_assert_eq (layout->num_members, 14, "all DemoStruct members are reachable");
	mu_assert_eq (layout->members[2].member_id, 2, "third field ordinal is exact");
	mu_assert_eq (layout->members[2].count, 1,
		"scalar aggregate members use the canonical single-element count");
	mu_assert_streq (layout->members[2].name, "third", "third field label is preserved");
	mu_assert_eq (layout->members[2].offset_bits, 8 * 8, "third field offset is eight bytes");
	mu_assert_eq (layout->members[13].member_id, 13, "fourteenth field ordinal is exact");
	mu_assert_streq (layout->members[13].name, "fourteenth",
		"fourteenth field label is preserved");
	mu_assert_eq (layout->members[13].offset_bits, 52 * 8,
		"fourteenth field offset is 52 bytes");
	mu_assert_eq (arr->carrier.kind, R_ANAL_SNAPSHOT_CARRIER_FULL,
		"pointer consumes its full 64-bit ABI carrier");
	mu_assert_eq (arr->carrier.size_bits, 64, "pointer carrier projection is 64 bits");
	mu_assert_eq (idx->carrier.kind, R_ANAL_SNAPSHOT_CARRIER_LOW_BITS,
		"signed int32 parameter occupies the low carrier slice");
	mu_assert_eq (idx->carrier.offset_bits, 0, "integer carrier slice begins at bit zero");
	mu_assert_eq (idx->carrier.size_bits, 32, "integer carrier slice is 32 bits");
	mu_assert_eq (snapshot->function_interface.return_carrier.kind,
		R_ANAL_SNAPSHOT_CARRIER_LOW_BITS, "signed int32 return occupies the low carrier slice");
	mu_assert_eq (snapshot->function_interface.return_carrier.size_bits, 32,
		"return carrier slice is 32 bits");

	mu_assert_true (save_snapshot_demo_struct_type (anal, 52, 2),
		"replace DemoStruct with an array member");
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature),
		"refresh signature after array-layout mutation");
	RAnalFunctionSnapshot *rejected = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rejected, "legacy snapshot survives unsupported array layout");
	mu_assert_false (rejected->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"array layout is not certified by the closed exact subset");
	mu_assert_false (rejected->type_graph.complete, "rejected graph is not partially exposed");
	mu_assert_eq (rejected->function_interface.parameters[0].logical_type_id,
		R_ANAL_SNAPSHOT_TYPE_ID_INVALID, "rejected graph clears parameter logical refs");
	mu_assert_eq (rejected->function_interface.return_type_id,
		R_ANAL_SNAPSHOT_TYPE_ID_INVALID, "rejected graph clears return logical ref");
	mu_assert_true (snapshot->type_graph.complete,
		"previous exact graph remains immutable after live type mutation");
	mu_assert_eq (layout->members[13].count, 1,
		"previous exact aggregate retains its owned non-array member");
	r_anal_function_snapshot_free (rejected);

	mu_assert_true (save_snapshot_demo_struct_type (anal, 48, 0),
		"replace DemoStruct with an overlapping member");
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature),
		"refresh signature after overlap mutation");
	rejected = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rejected, "legacy snapshot survives overlapping layout");
	mu_assert_false (rejected->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"overlapping layout is not certified");
	r_anal_function_snapshot_free (rejected);

	mu_assert_true (save_snapshot_demo_struct_type (anal, 52, 0),
		"restore exact DemoStruct layout");
	RAnalBaseType *alias = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	alias->name = strdup ("DemoStruct");
	alias->type = strdup ("struct DemoStruct");
	r_anal_save_base_type (anal, alias);
	r_anal_base_type_free (alias);
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature),
		"refresh signature after ambiguous alias mutation");
	rejected = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rejected, "legacy snapshot survives ambiguous bare type");
	mu_assert_false (rejected->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"same bare name in tag and typedef namespaces fails closed");
	r_anal_function_snapshot_free (rejected);

	r_anal_function_snapshot_free (snapshot);
	r_list_free (parameters);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_seals_exact_scalar_pointer_graph(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create exact scalar-pointer analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	sdb_reset (anal->sdb_types);
	mu_assert_true (r_anal_cc_set (anal, "rax exactscalarptr(rdi,rsi)"),
		"seed exact scalar-pointer calling convention");

	RAnalFunction *fcn = r_anal_create_function (
		anal, "typed_scalar_pointer_snapshot", 0x7900, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create exact scalar-pointer function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back scalar-pointer snapshot with exact bytes");
	RAnalFunctionParam parameters_data[] = {
		{ .name = "bytes", .type = "uint8_t *" },
		{ .name = "length", .type = "uint64_t" },
	};
	RList *parameters = r_list_new ();
	mu_assert_notnull (parameters, "create exact scalar-pointer parameter list");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (parameters_data); i++) {
		mu_assert_true (r_list_append (parameters, &parameters_data[i]),
			"append exact scalar-pointer parameter");
	}
	RAnalFunctionSignature signature = {
		.ret_type = "uint64_t",
		.callconv = "exactscalarptr",
		.params = parameters,
	};
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature),
		"apply exact scalar-pointer signature");
	mu_assert_true (set_function_type_link (anal, fcn->name, fcn->addr),
		"link exact scalar-pointer signature by address");
	r_list_free (parameters);

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect exact scalar-pointer type graph");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"exact scalar-pointer function-types capability is present");
	mu_assert_true (snapshot->type_graph.complete,
		"exact scalar-pointer graph is complete");
	mu_assert_true (snapshot->function_interface.logical_types_complete,
		"scalar-pointer logical values are complete");
	mu_assert_eq (snapshot->type_graph.num_types, 3,
		"reachable graph contains byte, byte pointer, and uint64 nodes");
	mu_assert_eq (snapshot->type_graph.num_aggregates, 0,
		"scalar pointee does not invent an aggregate");

	const RAnalSnapshotParameter *bytes =
		&snapshot->function_interface.parameters[0];
	const RAnalSnapshotParameter *length =
		&snapshot->function_interface.parameters[1];
	mu_assert ("scalar pointer logical type id is valid",
		bytes->logical_type_id < snapshot->type_graph.num_types);
	const RAnalSnapshotType *pointer =
		&snapshot->type_graph.types[bytes->logical_type_id];
	mu_assert_eq (pointer->kind, R_ANAL_SNAPSHOT_TYPE_POINTER,
		"byte parameter is an exact pointer node");
	mu_assert_eq (pointer->size_bits, 64, "byte pointer width is sealed");
	mu_assert ("scalar pointer target id is valid",
		pointer->target_type_id < snapshot->type_graph.num_types);
	const RAnalSnapshotType *pointee =
		&snapshot->type_graph.types[pointer->target_type_id];
	mu_assert_eq (pointee->kind, R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER,
		"byte pointer target is an exact unsigned scalar");
	mu_assert_eq (pointee->size_bits, 8, "byte pointee width is exact");
	mu_assert_eq (pointee->align_bits, 8, "byte pointee alignment is exact");
	mu_assert_eq (length->logical_type_id,
		snapshot->function_interface.return_type_id,
		"length and return share the uint64 logical node");
	const RAnalSnapshotType *word =
		&snapshot->type_graph.types[length->logical_type_id];
	mu_assert_eq (word->kind, R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER,
		"length and return remain unsigned");
	mu_assert_eq (word->size_bits, 64, "length and return width is exact");
	mu_assert_eq (bytes->carrier.kind, R_ANAL_SNAPSHOT_CARRIER_FULL,
		"byte pointer consumes its full ABI carrier");
	mu_assert_eq (length->carrier.kind, R_ANAL_SNAPSHOT_CARRIER_FULL,
		"uint64 length consumes its full ABI carrier");
	mu_assert_eq (snapshot->function_interface.return_carrier.kind,
		R_ANAL_SNAPSHOT_CARRIER_FULL,
		"uint64 return consumes its full ABI carrier");

	ut64 revision = snapshot->revision_identity;
	parameters = r_list_new ();
	mu_assert_notnull (parameters, "recreate scalar-pointer parameter list");
	parameters_data[0].type = "uint16_t *";
	for (i = 0; i < R_ARRAY_SIZE (parameters_data); i++) {
		mu_assert_true (r_list_append (parameters, &parameters_data[i]),
			"reappend mutated scalar-pointer parameter");
	}
	signature.params = parameters;
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature),
		"apply mutated scalar-pointer signature");
	r_list_free (parameters);
	RAnalFunctionSnapshot *mutated = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (mutated, "collect mutated scalar-pointer graph");
	mu_assert_true (mutated->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"supported scalar-pointee mutation stays exact");
	mu_assert_neq (mutated->revision_identity, revision,
		"scalar-pointee mutation changes snapshot revision");
	const RAnalSnapshotType *mutated_pointer = &mutated->type_graph.types[
		mutated->function_interface.parameters[0].logical_type_id];
	const RAnalSnapshotType *mutated_pointee =
		&mutated->type_graph.types[mutated_pointer->target_type_id];
	mu_assert_eq (mutated_pointee->size_bits, 16,
		"new snapshot owns the mutated scalar-pointee width");
	mu_assert_eq (pointee->size_bits, 8,
		"previous snapshot retains its owned byte-pointee width");

	r_anal_function_snapshot_free (mutated);
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_resolves_lp64_integer_typedefs(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create LP64 typedef analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	sdb_reset (anal->sdb_types);
	mu_assert_true (save_snapshot_atomic_type (anal, "uint64_t", "q", 64),
		"seed stale built-in uint64 atomic");
	mu_assert_true (save_snapshot_atomic_type (anal, "uint32_t", "d", 32),
		"seed stale built-in uint32 atomic");
	mu_assert_true (save_snapshot_typedef_type (anal, "uint64_t", "unsigned long long"),
		"seed DWARF-style uint64 typedef");
	mu_assert_true (save_snapshot_typedef_type (anal, "uint32_t", "unsigned int"),
		"seed DWARF-style uint32 typedef");
	sdb_set (anal->sdb_types, "unsigned_long_long", "type", 0);
	sdb_num_set (anal->sdb_types, "type.unsigned_long_long.size", 64, 0);
	sdb_set (anal->sdb_types, "unsigned_int", "type", 0);
	sdb_num_set (anal->sdb_types, "type.unsigned_int.size", 32, 0);
	r_anal_types_bump_dirty_epoch (anal);
	mu_assert_true (r_anal_cc_set (anal, "rax lp64types(rdi,rsi)"),
		"seed LP64 typedef calling convention");

	RAnalFunction *fcn = r_anal_create_function (
		anal, "lp64_typedef_snapshot", 0x7a00, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create LP64 typedef function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back LP64 typedef snapshot with exact bytes");
	sdb_set (anal->sdb_types, fcn->name, "func", 0);
	sdb_setf (anal->sdb_types, "uint64_t", 0, "func.%s.ret", fcn->name);
	sdb_setf (anal->sdb_types, "2", 0, "func.%s.args", fcn->name);
	sdb_setf (anal->sdb_types, "uint64_t,wide", 0, "func.%s.arg.0", fcn->name);
	sdb_setf (anal->sdb_types, "uint32_t,narrow", 0, "func.%s.arg.1", fcn->name);
	sdb_setf (anal->sdb_types, "wide,narrow", 0, "func.%s", fcn->name);
	sdb_setf (anal->sdb_types, "lp64types", 0, "func.%s.cc", fcn->name);
	r_anal_types_bump_dirty_epoch (anal);
	mu_assert_true (set_function_type_link (anal, fcn->name, fcn->addr),
		"link LP64 typedef signature by address");

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect LP64 typedef type graph");
	mu_assert_true (snapshot->function_interface.complete,
		"LP64 typedef physical interface is complete");
	mu_assert_notnull (snapshot->context.signature, "LP64 typedef signature is present");
	mu_assert_streq (snapshot->context.signature->ret_type, "uint64_t",
		"LP64 typedef return spelling is preserved");
	RAnalSnapshotCodePointerTableView table_view = {0};
	mu_assert_false (r_anal_function_snapshot_code_pointer_table_view (snapshot, 0, &table_view),
		"a function referencing no pointer table carries none");
	ut64 table_target = 0;
	mu_assert_false (r_anal_function_snapshot_code_pointer_table_target (snapshot, 0, 0, &table_target),
		"a table that was not collected hands out no target");
	RAnalFunctionSnapshotView callee_top = {0};
	mu_assert_true (r_anal_function_snapshot_view (snapshot, &callee_top),
		"read the top view for the callee snapshot count");
	mu_assert_eq (callee_top.num_callee_snapshots, 0,
		"a function that calls nothing carries no callee snapshot");
	mu_assert_null (r_anal_function_snapshot_callee_snapshot (snapshot, 0),
		"a callee snapshot that was not taken is not handed out");
	RAnalSnapshotSignatureView signature_view = {0};
	mu_assert_true (r_anal_function_snapshot_signature_view (snapshot, &signature_view),
		"the recovered signature is offered to a reader");
	mu_assert_eq (signature_view.num_parameters, 2,
		"the offered signature keeps both parameters");
	char spelling[64];
	mu_assert_true (r_anal_function_snapshot_signature_string (snapshot,
		R_ANAL_SNAPSHOT_SIGNATURE_STRING_RETURN_TYPE, 0, spelling, sizeof (spelling)),
		"the return spelling is readable");
	mu_assert_streq (spelling, "uint64_t", "the return spelling is the source's");
	mu_assert_true (r_anal_function_snapshot_signature_string (snapshot,
		R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_TYPE, 1, spelling, sizeof (spelling)),
		"the second parameter spelling is readable");
	mu_assert_streq (spelling, "uint32_t", "the parameter spelling is the source's");
	mu_assert_true (r_anal_function_snapshot_signature_string (snapshot,
		R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_NAME, 1, spelling, sizeof (spelling)),
		"the second parameter name is readable");
	mu_assert_streq (spelling, "narrow", "the parameter name is the source's");
	mu_assert_false (r_anal_function_snapshot_signature_string (snapshot,
		R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_TYPE, 2, spelling, sizeof (spelling)),
		"a parameter the signature does not have is refused");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"LP64 typedef graph carries exact type authority");
	mu_assert_true (snapshot->function_interface.logical_types_complete,
		"LP64 typedef logical values are complete");
	const RAnalSnapshotParameter *wide = &snapshot->function_interface.parameters[0];
	const RAnalSnapshotParameter *narrow = &snapshot->function_interface.parameters[1];
	mu_assert ("LP64 typedef type id is valid",
		wide->logical_type_id < snapshot->type_graph.num_types);
	mu_assert ("uint32 type id is valid",
		narrow->logical_type_id < snapshot->type_graph.num_types);
	const RAnalSnapshotType *wide_type =
		&snapshot->type_graph.types[wide->logical_type_id];
	const RAnalSnapshotType *narrow_type =
		&snapshot->type_graph.types[narrow->logical_type_id];
	mu_assert_eq (wide_type->kind, R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER,
		"LP64 typedef preserves unsignedness");
	mu_assert_eq (wide_type->size_bits, 64,
		"LP64 typedef width comes from its sized DWARF terminal");
	mu_assert_eq (narrow_type->kind, R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER,
		"uint32 interface preserves unsignedness");
	mu_assert_eq (narrow_type->size_bits, 32,
		"uint32 width comes from authoritative type state");
	mu_assert_eq (wide->logical_type_id, snapshot->function_interface.return_type_id,
		"LP64 parameter and return share structural identity");
	mu_assert_eq (wide->carrier.kind, R_ANAL_SNAPSHOT_CARRIER_FULL,
		"LP64 typedef consumes its full carrier");
	mu_assert_eq (wide->carrier.size_bits, 64,
		"LP64 typedef carrier projection is 64 bits");
	mu_assert_eq (narrow->carrier.kind, R_ANAL_SNAPSHOT_CARRIER_LOW_BITS,
		"uint32 projects into the low carrier bits");
	mu_assert_eq (narrow->carrier.size_bits, 32,
		"uint32 carrier projection is 32 bits");
	mu_assert_notnull (find_snapshot_base_type_kind (snapshot, "uint64_t",
		R_ANAL_BASE_TYPE_KIND_TYPEDEF), "snapshot owns the current uint64 typedef root");
	mu_assert_null (find_snapshot_base_type_kind (snapshot, "uint64_t",
		R_ANAL_BASE_TYPE_KIND_ATOMIC), "snapshot excludes the stale same-name atomic root");
	RAnalBaseType *owned_terminal = find_snapshot_base_type_kind (
		snapshot, "unsigned_long_long", R_ANAL_BASE_TYPE_KIND_ATOMIC);
	mu_assert_notnull (owned_terminal, "snapshot owns the encoding-less DWARF terminal");
	mu_assert_null (owned_terminal->type,
		"encoding-less terminal stays distinct from an encoded atomic");
	mu_assert_eq (owned_terminal->size, 64,
		"snapshot owns the terminal width used by the logical graph");
	const ut64 revision = snapshot->revision_identity;
	sdb_num_set (anal->sdb_types, "type.unsigned_long_long.size", 32, 0);
	mu_assert_eq (owned_terminal->size, 64,
		"raw type database mutation cannot alter captured resolver state");
	RAnalFunctionSnapshot *raw_mutated = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (raw_mutated, "collect snapshot after raw resolver mutation");
	mu_assert_false (raw_mutated->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"new snapshot observes a raw mismatched terminal mutation");
	mu_assert_neq (raw_mutated->revision_identity, revision,
		"owned resolver metadata participates in snapshot revision");
	r_anal_function_snapshot_free (raw_mutated);
	sdb_num_set (anal->sdb_types, "type.unsigned_long_long.size", 64, 0);
	sdb_set (anal->sdb_types, "uint64_t", "type", 0);
	RAnalFunctionSnapshot *raw_root_mutated = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (raw_root_mutated, "collect snapshot after raw root-kind mutation");
	mu_assert_true (raw_root_mutated->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"current same-width atomic root remains exact");
	mu_assert_notnull (find_snapshot_base_type_kind (raw_root_mutated, "uint64_t",
		R_ANAL_BASE_TYPE_KIND_ATOMIC), "new snapshot owns the current atomic root");
	mu_assert_null (find_snapshot_base_type_kind (raw_root_mutated, "uint64_t",
		R_ANAL_BASE_TYPE_KIND_TYPEDEF), "new snapshot excludes the stale typedef root");
	mu_assert_neq (raw_root_mutated->revision_identity, revision,
		"current root-kind selection participates in snapshot revision");
	r_anal_function_snapshot_free (raw_root_mutated);
	sdb_set (anal->sdb_types, "uint64_t", "typedef", 0);
	r_anal_function_snapshot_free (snapshot);

	sdb_num_set (anal->sdb_types, "type.unsigned_long_long.size", 32, 0);
	r_anal_types_bump_dirty_epoch (anal);
	RAnalFunctionSnapshot *rejected = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rejected, "collect mismatched typedef snapshot");
	mu_assert_false (rejected->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"fixed-width typedef rejects mismatched terminal width");
	mu_assert_false (rejected->function_interface.logical_types_complete,
		"mismatched typedef exposes no partial logical graph");
	r_anal_function_snapshot_free (rejected);

	sdb_num_set (anal->sdb_types, "type.unsigned_long_long.size", 64, 0);
	r_anal_types_bump_dirty_epoch (anal);
	RAnalBaseType *collision = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	mu_assert_notnull (collision, "create conflicting uint64 tag");
	collision->name = strdup ("uint64_t");
	collision->size = 32;
	RAnalStructMember member = {
		.name = strdup ("value"),
		.type = strdup ("uint32_t"),
	};
	mu_assert_notnull (collision->name, "name conflicting uint64 tag");
	mu_assert_notnull (member.name, "name conflicting uint64 member");
	mu_assert_notnull (member.type, "type conflicting uint64 member");
	RAnalStructMember *collision_member = RVecAnalTypeMember_emplace_back (
		&collision->struct_data.members);
	mu_assert_notnull (collision_member, "append conflicting uint64 member");
	*collision_member = member;
	r_anal_save_base_type (anal, collision);
	r_anal_base_type_free (collision);
	mu_assert_true (save_snapshot_typedef_type (anal, "uint64_t", "unsigned long long"),
		"restore current typedef root beside conflicting tag");
	rejected = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (rejected, "collect ambiguous typedef snapshot");
	mu_assert_false (rejected->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES,
		"current typedef and same-name tag fail closed");
	mu_assert_false (rejected->function_interface.logical_types_complete,
		"ambiguous root exposes no partial logical graph");
	r_anal_function_snapshot_free (rejected);

	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_seals_exact_call_site_interfaces(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create callsite snapshot analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax exactcall(rdi)"),
		"seed exact callsite calling convention");

	RAnalFunction *caller = r_anal_create_function (
		anal, "callsite_caller", 0x8000, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *callee = r_anal_create_function (
		anal, "callsite_callee", 0x9000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (caller, "create callsite caller");
	mu_assert_notnull (callee, "create callsite callee");
	RAnalBlock *block = r_anal_create_block (anal, 0x8000, 0x20);
	mu_assert_notnull (block, "create caller block");
	block->ninstr = 2;
	mu_assert_true (r_anal_bb_set_offset (block, 0, 0), "record caller entry instruction");
	mu_assert_true (r_anal_bb_set_offset (block, 1, 0x10), "record raw call instruction");
	r_anal_function_add_block (caller, block);
	r_unref (block);
	RAnalBlock *callee_block = r_anal_create_block (anal, 0x9000, 1);
	mu_assert_notnull (callee_block, "create callee block");
	r_anal_function_add_block (callee, callee_block);
	r_unref (callee_block);
	RAnalFunctionParam argument = {
		.name = "value",
		.type = "int64_t",
	};
	RList *arguments = r_list_new ();
	mu_assert_notnull (arguments, "create callsite arguments");
	mu_assert_true (r_list_append (arguments, &argument), "append callsite argument");
	RAnalFunctionSignature signature = {
		.ret_type = "void",
		.callconv = "exactcall",
		.params = arguments,
	};
	mu_assert_true (r_anal_function_set_signature (anal, callee, &signature),
		"apply exact callee signature");
	r_list_free (arguments);
	mu_assert_true (r_anal_xrefs_setf (
		anal, caller, 0x8010, 0x9000, R_ANAL_REF_TYPE_CALL),
		"record direct callsite");

	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, caller, NULL);
	mu_assert_notnull (snapshot, "collect exact callsite snapshot");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_CALL_SITE_INTERFACES,
		"callsite snapshot capability is present");
	mu_assert_eq (snapshot->num_call_site_interfaces, 1, "one exact callsite interface");
	RAnalCallSiteInterfaceSnapshot *call = &snapshot->call_site_interfaces[0];
	mu_assert_eq (call->instruction_addr, 0x8010, "raw call instruction identity");
	mu_assert_eq (call->target_addr, 0x9000, "raw direct target identity");
	mu_assert_notnull (call->calling_convention, "exact callsite calling convention is present");
	mu_assert_streq (call->calling_convention, "exactcall", "exact callsite calling convention");
	mu_assert_eq (call->num_arguments, 1, "one exact call argument");
	mu_assert_eq (call->arguments[0].index, 0, "exact call argument order");
	mu_assert_streq (call->arguments[0].storage.name, "rdi", "full-width call argument register");
	mu_assert_eq (call->arguments[0].storage.size, 8, "full-width call argument size");
	mu_assert_eq (call->result_kind, R_ANAL_SNAPSHOT_RETURN_VOID, "void call result contract");
	// Completeness describes the prototype, not the call instruction. The xref
	// establishes which callee is reached, so the argument and result carriers
	// resolved from that callee's signature are exactly as good as the
	// signature itself, and a call site is complete exactly when both resolved.
	mu_assert_true (call->complete,
		"an xref-derived callsite reports the prototype it recovered");
	mu_assert_false (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_CALL_SITE_INTERFACES,
		"xref-derived callsite cannot mint exact authority");

	ut64 revision = snapshot->revision_identity;
	callee->is_variadic = true;
	r_anal_function_bump_dirty_epoch (callee);
	RAnalFunctionSnapshot *variadic = r_anal_function_snapshot_collect_bounded (anal, caller, NULL);
	mu_assert_notnull (variadic, "collect variadic callsite snapshot");
	mu_assert_true (variadic->call_site_interfaces[0].variadic,
		"the callsite records that the callee is variadic");
	mu_assert_true (variadic->call_site_interfaces[0].complete,
		"a variadic callee still places its fixed arguments and its result");
	mu_assert_false (variadic->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_CALL_SITE_INTERFACES,
		"variadic callsite omits exact capability");
	mu_assert_neq (variadic->revision_identity, revision,
		"callsite contract mutation changes caller snapshot revision");
	r_anal_function_snapshot_free (variadic);
	callee->is_variadic = false;
	r_anal_function_bump_dirty_epoch (callee);

	// ...and not otherwise: a prototype the convention cannot place leaves the
	// arguments unresolved, and the callsite says so.
	RAnalFunctionParam unplaceable_argument = {
		.name = "second",
		.type = "int64_t",
	};
	arguments = r_list_new ();
	mu_assert_notnull (arguments, "create unplaceable callsite arguments");
	mu_assert_true (r_list_append (arguments, &argument), "append first unplaceable argument");
	mu_assert_true (r_list_append (arguments, &unplaceable_argument),
		"append second unplaceable argument");
	signature.params = arguments;
	mu_assert_true (r_anal_function_set_signature (anal, callee, &signature),
		"apply a prototype the one-register convention cannot place");
	r_list_free (arguments);
	RAnalFunctionSnapshot *incomplete = r_anal_function_snapshot_collect_bounded (anal, caller, NULL);
	mu_assert_notnull (incomplete, "collect unplaceable-argument callsite snapshot");
	mu_assert_eq (incomplete->num_call_site_interfaces, 1, "one unplaceable callsite");
	mu_assert_eq (incomplete->call_site_interfaces[0].num_arguments, 2,
		"the unplaceable prototype still reports both arguments");
	mu_assert_false (incomplete->call_site_interfaces[0].complete,
		"an argument the convention cannot place leaves the callsite incomplete");
	mu_assert_false (incomplete->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_CALL_SITE_INTERFACES,
		"incomplete callsite omits exact capability");
	r_anal_function_snapshot_free (incomplete);
	arguments = r_list_new ();
	mu_assert_notnull (arguments, "recreate placeable callsite arguments");
	mu_assert_true (r_list_append (arguments, &argument), "reappend placeable argument");
	signature.params = arguments;
	mu_assert_true (r_anal_function_set_signature (anal, callee, &signature),
		"restore the placeable callee prototype");
	r_list_free (arguments);
	RAnalFunction *second_callee = r_anal_create_function (
		anal, "callsite_callee_ambiguous", 0x9100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (second_callee, "create ambiguous second callee");
	RAnalBlock *second_block = r_anal_create_block (anal, 0x9100, 1);
	mu_assert_notnull (second_block, "create ambiguous second callee block");
	r_anal_function_add_block (second_callee, second_block);
	r_unref (second_block);
	arguments = r_list_new ();
	mu_assert_notnull (arguments, "recreate ambiguous callsite arguments");
	mu_assert_true (r_list_append (arguments, &argument), "append ambiguous callsite argument");
	signature.params = arguments;
	mu_assert_true (r_anal_function_set_signature (anal, second_callee, &signature),
		"apply second exact callee signature");
	r_list_free (arguments);
	mu_assert_true (r_anal_xrefs_setf (
		anal, caller, 0x8010, 0x9100, R_ANAL_REF_TYPE_CALL),
		"record ambiguous raw callsite target");
	RAnalFunctionSnapshot *ambiguous = r_anal_function_snapshot_collect_bounded (anal, caller, NULL);
	mu_assert_notnull (ambiguous, "collect ambiguous raw callsite snapshot");
	mu_assert_eq (ambiguous->num_call_site_interfaces, 2,
		"ambiguous raw address preserves both generic source facts");
	mu_assert_eq (ambiguous->call_site_interfaces[0].instruction_addr,
		ambiguous->call_site_interfaces[1].instruction_addr,
		"ambiguous source facts retain their shared raw instruction");
	mu_assert_false (ambiguous->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_CALL_SITE_INTERFACES,
		"ambiguous raw callsite omits exact-set capability");
	r_anal_function_snapshot_free (ambiguous);
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_snapshot_rejects_inexact_stack_resources(void) {
	RCore *core = snapshot_test_core_new ();
	RAnal *anal = core? core->anal: NULL;
	mu_assert_notnull (anal, "create stack-resource analysis");
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	mu_assert_true (r_anal_cc_set (anal, "rax stackcc(rdi)"), "seed stack-resource calling convention");

	RAnalFunction *fcn = r_anal_create_function (
		anal, "stack_snapshot", 0x7080, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create stack-resource function");
	mu_assert_true (snapshot_test_ensure_block (anal, fcn, 1),
		"back stack-resource snapshot with exact bytes");
	RAnalFunctionParam parameter = {
		.name = "value",
		.type = "int64_t",
	};
	RList *parameters = r_list_new ();
	mu_assert_notnull (parameters, "create stack-resource parameter list");
	mu_assert_true (r_list_append (parameters, &parameter), "append stack-resource parameter");
	RAnalFunctionSignature signature = {
		.ret_type = "int64_t",
		.callconv = "stackcc",
		.params = parameters,
	};
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &signature), "apply stack-resource signature");
	mu_assert_true (set_function_type_link (anal, fcn->name, fcn->addr),
		"link stack-resource signature by address");
	r_list_free (parameters);

	RAnalVar *first = r_anal_function_set_var (
		fcn, -8, R_ANAL_VAR_KIND_BPV, "int64_t", 8, false, "first_slot");
	RAnalVar *second = r_anal_function_set_var (
		fcn, -4, R_ANAL_VAR_KIND_BPV, "int32_t", 4, false, "overlap_slot");
	mu_assert_notnull (first, "create first overlapping slot");
	mu_assert_notnull (second, "create second overlapping slot");
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect overlapping resource snapshot");
	mu_assert_false (snapshot->function_interface.stack_resources_complete,
		"overlapping resources on one base are incomplete");
	// The frame extent is a claim of the stack slot roles, not of the
	// interface: slots that overlap cannot prove they do not, so the roles lose
	// their exactness while the carriers recovered without reference to the
	// frame keep theirs.
	mu_assert_false (snapshot->function_interface.stack_slot_roles_complete,
		"overlap rejects the exact frame extent claim");
	mu_assert_false (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES,
		"overlap omits exact stack-slot-role capability");
	mu_assert_true (snapshot->function_interface.complete,
		"overlap leaves the parameter and return carriers certified");
	mu_assert_true (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE,
		"overlap keeps the exact-interface capability the frame does not decide");
	mu_assert_eq (snapshot->function_interface.num_parameters, 1,
		"overlap still reports the recovered parameter");
	mu_assert_streq (snapshot->function_interface.parameters[0].storage.name, "rdi",
		"overlap still names the parameter carrier it recovered");
	mu_assert_eq (snapshot->function_interface.return_kind,
		R_ANAL_SNAPSHOT_RETURN_REGISTER, "overlap still reports the result carrier");
	mu_assert_streq (snapshot->function_interface.return_storage.name, "rax",
		"overlap still names the result carrier it recovered");
	r_anal_function_snapshot_free (snapshot);

	mu_assert_true (r_anal_var_delete (anal, second), "remove overlapping resource");
	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_BP, "not_a_register"),
		"make BP base identity unknown");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect unknown-base resource snapshot");
	RAnalFcnSlot *unknown = find_stack_slot (&snapshot->context, "first_slot");
	mu_assert_notnull (unknown, "unknown-base resource stays in immutable snapshot");
	mu_assert_null (unknown->base_name, "unknown base has no exact register name");
	mu_assert_false (snapshot->function_interface.stack_resources_complete,
		"unknown base rejects complete stack resources");
	r_anal_function_snapshot_free (snapshot);

	mu_assert_true (r_reg_alias_setname (anal->reg, R_REG_ALIAS_BP, "rbp"), "restore BP identity");
	r_anal_var_set_type (anal, first, "missing_stack_resource_type");
	snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	mu_assert_notnull (snapshot, "collect unknown-size resource snapshot");
	RAnalFcnSlot *unknown_size = find_stack_slot (&snapshot->context, "first_slot");
	mu_assert_notnull (unknown_size, "unknown-size resource stays in immutable snapshot");
	mu_assert_eq (unknown_size->size, 0, "unknown type does not invent a resource size");
	mu_assert_false (snapshot->function_interface.stack_resources_complete,
		"unknown size rejects complete stack resources");
	r_anal_function_snapshot_free (snapshot);
	r_core_free (core);
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
	mu_run_test (test_r_anal_function_get_signature);
	mu_run_test (test_r_anal_function_get_signature_prefers_exact_type_link);
	mu_run_test (test_r_anal_function_set_signature_uses_canonical_type_name);
	mu_run_test (test_r_anal_function_get_signature_string_uses_import_flag_name);
	mu_run_test (test_r_anal_function_get_signature_uses_basename_for_dbg_prefixed_function);
	mu_run_test (test_r_anal_function_get_signature_string_falls_back_to_vars);
	mu_run_test (test_r_anal_function_get_signature_string_hides_variadic_placeholder);
	mu_run_test (test_r_anal_function_get_signature_falls_back_to_valid_callconv);
	mu_run_test (test_r_anal_function_context_collect_is_conservative_for_stack_slots);
	mu_run_test (test_r_anal_function_snapshot_reads_current_state_only);
	mu_run_test (test_r_anal_function_snapshot_does_not_mutate_var_cache);
	mu_run_test (test_r_anal_function_snapshot_distinguishes_split_fallthrough);
	mu_run_test (test_r_anal_function_snapshot_limits_bound_type_clone);
	mu_run_test (test_r_anal_function_snapshot_seals_exact_register_interface);
	mu_run_test (test_r_anal_function_snapshot_prefers_link_register_return_address);
	mu_run_test (test_r_anal_function_snapshot_falls_back_from_unusable_linked_cc);
	mu_run_test (test_r_anal_function_snapshot_seals_exact_reachable_type_graph);
	mu_run_test (test_r_anal_function_snapshot_seals_exact_scalar_pointer_graph);
	mu_run_test (test_r_anal_function_snapshot_resolves_lp64_integer_typedefs);
	mu_run_test (test_r_anal_function_snapshot_seals_exact_call_site_interfaces);
	mu_run_test (test_r_anal_function_snapshot_rejects_inexact_stack_resources);
	mu_run_test (test_r_anal_apply_mutations_atomic_is_all_or_nothing);
	mu_run_test (test_r_anal_apply_mutations_atomic_rejects_unsupported_preflight);
	mu_run_test (test_r_anal_apply_mutations_atomic_rolls_back_commit_conflict);
	mu_run_test (test_r_anal_apply_mutations_atomic_defers_publication);
	mu_run_test (test_r_anal_function_switches_foreach);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
