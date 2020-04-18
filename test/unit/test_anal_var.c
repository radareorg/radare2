#include <r_anal.h>
#include "minunit.h"

static bool sanitize_instr_acc(void *user, const ut64 k, const void *v) {
	RPVector *vec = v;
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

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	assert_sane (anal);

	RAnalVar *a = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "char *", 8, false, "var_a");
	RAnalVar *b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_BPV, "char *", 8, false, "var_a");

	r_anal_var_set_access (a, 0x120, R_ANAL_VAR_ACCESS_TYPE_READ, 42);
	r_anal_var_set_access (a, 0x130, R_ANAL_VAR_ACCESS_TYPE_WRITE, 13);
	r_anal_var_set_access (b, 0x120, R_ANAL_VAR_ACCESS_TYPE_WRITE, 42);

	assert_sane (anal);

	r_anal_var_delete (a);

	assert_sane (anal);

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
