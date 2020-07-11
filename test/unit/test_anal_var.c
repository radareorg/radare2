#include <r_anal.h>
#include "minunit.h"

static bool sanitize_instr_acc(void *user, const ut64 k, const void *v) {
	RPVector *vec = (RPVector *)v;
	void **it;
	r_pvector_foreach (vec, it) {
		RAnalVar *var = *it;
		RAnalVarAccess *acc;
		bool found = false;
		r_vector_foreach (&var->accesses, acc) {
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

	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		RAnalVarAccess *acc;
		r_vector_foreach (&var->accesses, acc) {
			RPVector *iaccs = ht_up_find (fcn->inst_vars, acc->offset, NULL);
			mu_assert ("var refs instr but instr does not ref var", r_pvector_contains (iaccs, var));
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

bool test_r_anal_var() {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	assert_sane (anal);

	// creating variables and renaming

	RAnalVar *a = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "char *", 8, false, "random_name");
	mu_assert_notnull (a, "create a var");
	mu_assert_streq (a->name, "random_name", "var name");
	bool succ = r_anal_var_rename (a, "var_a", false);
	mu_assert ("rename success", succ);
	mu_assert_streq (a->name, "var_a", "var name after rename");

	RAnalVar *b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_SPV, "char *", 8, false, "var_a");
	mu_assert_null (b, "create a var with the same name");
	b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_SPV, "char *", 8, false, "new_var");
	mu_assert_notnull (b, "create a var with another name");
	mu_assert_streq (b->name, "new_var", "var name");
	succ = r_anal_var_rename (b, "random_name", false);
	mu_assert ("rename success", succ);
	mu_assert_streq (b->name, "random_name", "var name after rename");
	succ = r_anal_var_rename (b, "var_a", false);
	mu_assert ("rename failed", !succ);
	mu_assert_streq (b->name, "random_name", "var name after failed rename");
	succ = r_anal_var_rename (b, "var_b", false);
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

	r_anal_var_set_access (a, "rsp", 0x120, R_ANAL_VAR_ACCESS_TYPE_READ, 42);
	r_anal_var_set_access (a, "rbp", 0x130, R_ANAL_VAR_ACCESS_TYPE_WRITE, 13);
	r_anal_var_set_access (b, "rsp", 0x120, R_ANAL_VAR_ACCESS_TYPE_WRITE, 123);
	r_anal_var_set_access (b, "rbp", 0x10, R_ANAL_VAR_ACCESS_TYPE_WRITE, -100);

	st64 stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x12345);
	mu_assert_eq (stackptr, ST64_MAX, "unset stackptr");

	RPVector *used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("no used vars", !used_vars || r_pvector_len (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x130);
	mu_assert_eq (stackptr, 13, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, 123123, 0x130);
	mu_assert_eq (stackptr, ST64_MAX, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x120);
	mu_assert_eq (r_pvector_len (used_vars), 2, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	mu_assert ("used vars", r_pvector_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x120);
	mu_assert_eq (stackptr, 42, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x10);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x10);
	mu_assert_eq (stackptr, -100, "stackptr");

	assert_sane (anal);

	// relocate function

	r_anal_function_relocate (fcn, 0xffffffffffff0100UL);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL); // addresses should stay the same
	mu_assert ("no used vars", !used_vars || r_pvector_len (used_vars));
	r_anal_var_set_access (a, "rbp", 0xffffffffffff0130UL, R_ANAL_VAR_ACCESS_TYPE_READ, 42);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("no used vars", !used_vars || r_pvector_len (used_vars));
	r_anal_var_set_access (a, "rbp" , 0x123, R_ANAL_VAR_ACCESS_TYPE_READ, 42);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x120);
	mu_assert_eq (r_pvector_len (used_vars), 2, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	mu_assert ("used vars", r_pvector_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x120);
	mu_assert_eq (stackptr, 42, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x10);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, b));

	r_anal_function_relocate (fcn, 0x8000000000000010);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000100);
	mu_assert ("no used vars", !used_vars || r_pvector_len (used_vars));
	r_anal_var_set_access (a, "rbp", 0x8000000000000100, R_ANAL_VAR_ACCESS_TYPE_READ, 987321);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000100);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x8000000000000100);
	mu_assert_eq (stackptr, 987321, "stackptr");

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x7ffffffffffffe00);
	mu_assert ("no used vars", !used_vars || r_pvector_len (used_vars));
	r_anal_var_set_access (a, "rbp", 0x7ffffffffffffe00, R_ANAL_VAR_ACCESS_TYPE_READ, 777);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x7ffffffffffffe00);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x7ffffffffffffe00);
	mu_assert_eq (stackptr, 777, "stackptr");

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x120);
	mu_assert_eq (r_pvector_len (used_vars), 2, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, a));
	mu_assert ("used vars", r_pvector_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x120);
	mu_assert_eq (stackptr, 42, "stackptr");

	assert_sane (anal);

	r_anal_var_delete (a);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert ("used vars count", !used_vars || !r_pvector_len (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("used vars count", !used_vars || !r_pvector_len (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert ("used vars count", !used_vars || !r_pvector_len (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x120);
	mu_assert_eq (r_pvector_len (used_vars), 1, "used vars count");
	mu_assert ("used vars", r_pvector_contains (used_vars, b));

	r_anal_var_delete (b);
	r_anal_var_delete (c);

	r_anal_free (anal);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_anal_var);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
