#include <r_anal.h>
#include "minunit.h"

static int reg_index(RAnal *anal, const char *name) {
	RRegItem *ri = r_reg_get (anal->reg, name, -1);
	int index = ri? ri->index: -1;
	r_unref (ri);
	return index;
}

static bool vec_contains(RVecAnalVarPtr *vec, RAnalVar *var) {
	if (!vec) {
		return false;
	}
	RAnalVar **it;
	R_VEC_FOREACH (vec, it) {
		if (*it == var) {
			return true;
		}
	}
	return false;
}

static RAnalFcnRegArg *find_register_param(RAnalFcnContext *ctx, const char *reg) {
	RListIter *iter;
	RAnalFcnRegArg *arg;
	if (!ctx || !ctx->reg_args || !reg) {
		return NULL;
	}
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
	if (!ctx || !ctx->slots || !name) {
		return NULL;
	}
	r_list_foreach (ctx->slots, iter, slot) {
		if (slot && slot->name && !strcmp (slot->name, name)) {
			return slot;
		}
	}
	return NULL;
}

static bool sanitize_instr_acc(void *user, const ut64 k, const void *v) {
	RVecAnalVarPtr *vec = (RVecAnalVarPtr *)v;
	RAnalVar **it;
	R_VEC_FOREACH (vec, it) {
		RAnalVar *var = *it;
		RAnalVarAccess *acc;
		bool found = false;
		R_VEC_FOREACH (&var->accesses, acc) {
			if (acc->offset == (st64)k) {
				found = true;
				break;
			}
		}
		mu_assert ("instr refs var, but var does not ref instr", found);
	}
	return true;
}

static bool sanitize(RAnalFunction *fcn) {
	ht_up_foreach (fcn->inst_vars, sanitize_instr_acc, NULL);

	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		RAnalVarAccess *acc;
		R_VEC_FOREACH (&var->accesses, acc) {
			RVecAnalVarPtr *iaccs = ht_up_find (fcn->inst_vars, acc->offset, NULL);
			mu_assert ("var refs instr but instr does not ref var", vec_contains (iaccs, var));
		}
	}
	return true;
}

#define assert_sane(anal) do { RListIter *ass_it; RAnalFunction *ass_fcn; \
	r_list_foreach ((anal)->fcns, ass_it, ass_fcn) { \
		if (!sanitize (ass_fcn)) { \
			return false; \
		} \
	} \
} while (0);

bool test_r_anal_var(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	assert_sane (anal);

	// creating variables and renaming

	RAnalVar *a = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "char *", 8, false, "random_name");
	mu_assert_notnull (a, "create a var");
	mu_assert_streq (a->name, "random_name", "var name");
	bool succ = r_anal_var_rename (anal, a, "var_a");
	mu_assert ("rename success", succ);
	mu_assert_streq (a->name, "var_a", "var name after rename");

	RAnalVar *b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_SPV, "char *", 8, false, "var_a");
	mu_assert_null (b, "create a var with the same name");
	b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_SPV, "char *", 8, false, "new_var");
	mu_assert_notnull (b, "create a var with another name");
	mu_assert_streq (b->name, "new_var", "var name");
	succ = r_anal_var_rename (anal, b, "random_name");
	mu_assert ("rename success", succ);
	mu_assert_streq (b->name, "random_name", "var name after rename");
	succ = r_anal_var_rename (anal, b, "var_a");
	mu_assert ("rename failed", !succ);
	mu_assert_streq (b->name, "random_name", "var name after failed rename");
	succ = r_anal_var_rename (anal, b, "var_b");
	mu_assert ("rename success", succ);
	mu_assert_streq (b->name, "var_b", "var name after rename");

	RAnalVar *c = r_anal_function_set_var (fcn, 0x30, R_ANAL_VAR_KIND_REG, "int64_t", 8, true, "arg42");
	mu_assert_notnull (c, "create a var");

	// querying variables

	RAnalVar *v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, 0x41);
	mu_assert_null (v, "get no var");
	v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, 0x30);
	mu_assert_ptreq (v, c, "get var (reg)");
	v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_SPV, -0x10);
	mu_assert_ptreq (v, b, "get var (sp)");
	v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, -8);
	mu_assert_ptreq (v, a, "get var (bp)");

	v = r_anal_function_get_var_byname (fcn, "random_name");
	mu_assert_null (v, "nonsense name");
	v = r_anal_function_get_var_byname (fcn, "var_a");
	mu_assert_ptreq (v, a, "get var by name");

	// accesses

	r_anal_var_set_access (anal, a, "rsp", 0x120, R_PERM_R, 42);
	r_anal_var_set_access (anal, a, "rbp", 0x130, R_PERM_W, 13);
	r_anal_var_set_access (anal, b, "rsp", 0x120, R_PERM_W, 123);
	r_anal_var_set_access (anal, b, "rbp", 0x10, R_PERM_W, -100);

	st64 stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x12345);
	mu_assert_eq (stackptr, ST64_MAX, "unset stackptr");

	RVecAnalVarPtr *used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x130);
	mu_assert_eq (stackptr, 13, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, 123123, 0x130);
	mu_assert_eq (stackptr, ST64_MAX, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x120);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 2, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x120);
	mu_assert_eq (stackptr, 42, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x10);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x10);
	mu_assert_eq (stackptr, -100, "stackptr");

	assert_sane (anal);

	// relocate function

	r_anal_function_relocate (fcn, 0xffffffffffff0100UL);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL); // addresses should stay the same
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp", 0xffffffffffff0130UL, R_PERM_R, 42);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp" , 0x123, R_PERM_R, 42);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0120);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 2, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0xffffffffffff0120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0xffffffffffff0120);
	mu_assert_eq (stackptr, 42, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0010);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, b));

	r_anal_function_relocate (fcn, 0x8000000000000010);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000100);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp", 0x8000000000000100, R_PERM_R, 987321);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000100);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x8000000000000100);
	mu_assert_eq (stackptr, 987321, "stackptr");

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x7ffffffffffffe00);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp", 0x7ffffffffffffe00, R_PERM_R, 777);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x7ffffffffffffe00);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x7ffffffffffffe00);
	mu_assert_eq (stackptr, 777, "stackptr");

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000040UL);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000010033);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000040);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000030);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 2, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x8000000000000030);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x8000000000000030);
	mu_assert_eq (stackptr, 42, "stackptr");

	assert_sane (anal);

	r_anal_var_delete (anal, a);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert ("used vars count", !used_vars || !RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("used vars count", !used_vars || !RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert ("used vars count", !used_vars || !RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000030);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, b));

	// serialization / RAnalVarProt
	RList *vps = r_anal_var_get_prots (fcn);
	mu_assert ("Failed r_anal_var_get_protos", vps && r_list_length (vps) == 2);

	char *serial = r_anal_var_prot_serialize (vps, true);
	mu_assert ("serial space", !strcmp (serial, "fs-16:var_b:char *, tr48:arg42:int64_t"));
	free (serial);

	serial = r_anal_var_prot_serialize (vps, false);
	mu_assert ("serial no space", !strcmp (serial, "fs-16:var_b:char *,tr48:arg42:int64_t"));
	free (serial);
	r_list_free (vps);

	vps = r_anal_var_deserialize ("ts-16:var_name:char **, tr48:var_name_b:size_t");
	mu_assert ("Failed r_anal_var_deserialize", vps && r_list_length (vps) == 2);

	RAnalVarProt *vp = (RAnalVarProt *)r_list_first (vps);
	mu_assert ("Deserialize name[0]", !strcmp (vp->name, "var_name") && !strcmp (vp->type, "char **"));
	vp = (RAnalVarProt *)r_list_last (vps);
	mu_assert ("Deserialize name[1]", !strcmp (vp->name, "var_name_b") && !strcmp (vp->type, "size_t"));

	mu_assert ("r_anal_function_set_var_prot", r_anal_function_set_var_prot (fcn, vps));
	mu_assert ("Setting first var from proto", !strcmp (b->name, "var_name") && !strcmp (b->type, "char **"));
	mu_assert ("Setting second var from proto", !strcmp (c->name, "var_name_b") && !strcmp (c->type, "size_t"));

	r_list_purge (vps);
	vp = R_NEW0 (RAnalVarProt);
	vp->name = strdup ("bad_name:`${}~|#@&<>,");
	vp->type = strdup ("bad_type:`${}~|#@&<>,");
	r_list_append (vps, vp);
	vp->kind = 'z';
	serial = r_anal_var_prot_serialize (vps, false);
	mu_assert ("Serializtion succeeded despite invalide kind", !serial);
	free (serial);

	vp->kind = R_ANAL_VAR_KIND_REG;
	serial = r_anal_var_prot_serialize (vps, false);
	mu_assert ("Serializtion filtered bad chars", serial && !strcmp ("fr0:bad_name_____________:bad_type:____________", serial));
	r_list_free (vps);
	free (serial);

	vps = r_anal_var_deserialize ("ts-16:v,r_name:char **");
	mu_assert ("No ',' in serialized name", !vps);

	r_anal_var_delete (anal, b);
	r_anal_var_delete (anal, c);

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

int all_tests(void) {
	mu_run_test (test_r_anal_var);
	mu_run_test (test_r_anal_function_context_collect_is_conservative_for_stack_slots);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
