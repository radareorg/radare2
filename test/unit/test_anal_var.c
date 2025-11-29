#include <r_anal.h>
#include "minunit.h"

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

int all_tests(void) {
	mu_run_test (test_r_anal_var);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
