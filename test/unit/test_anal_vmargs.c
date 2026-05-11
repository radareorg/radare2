#include <r_anal.h>
#include "minunit.h"

// Mimic the dalvik arch reg profile: v0..vN at contiguous offsets, so the
// bytecode register index equals the position in the reg profile.
static void load_dalvik_profile(RAnal *anal) {
	RStrBuf *sb = r_strbuf_new (
		"=PC	ip\n"
		"=SP	sp\n"
		"=BP	bp\n"
	);
	int i;
	for (i = 0; i < 16; i++) {
		r_strbuf_appendf (sb, "gpr\tv%d\t.32\t%d\t0\n", i, i * 4);
	}
	r_strbuf_appendf (sb, "gpr\tip\t.32\t%d\t0\n", 16 * 4);
	r_strbuf_appendf (sb, "gpr\tsp\t.32\t%d\t0\n", 16 * 4 + 4);
	r_strbuf_appendf (sb, "gpr\tbp\t.32\t%d\t0\n", 16 * 4 + 8);
	char *p = r_strbuf_drain (sb);
	r_reg_set_profile_string (anal->reg, p);
	free (p);
}

// Mimic the JVM arch reg profile: pc/sp/bp/r0 first, then l0..l15. So l0 is at
// reg-profile index 4, not 0. This is the case the JVM-specific anal plugin
// had to handle, and what the generic helper must keep working.
static void load_jvm_profile(RAnal *anal) {
	RStrBuf *sb = r_strbuf_new (
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"gpr	pc	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	bp	.32	8	0\n"
		"gpr	r0	.32	12	0\n"
	);
	int i;
	for (i = 0; i < 16; i++) {
		r_strbuf_appendf (sb, "gpr\tl%d\t.32\t%d\t0\n", i, 16 + i * 4);
	}
	char *p = r_strbuf_drain (sb);
	r_reg_set_profile_string (anal->reg, p);
	free (p);
}

// Dalvik-shaped profile: arg_first=3 + arg_count=3 must yield v3/v4/v5 with
// deltas 3, 4, 5 (since v0 sits at reg-profile index 0).
static bool test_vm_args_dalvik(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new");
	load_dalvik_profile (anal);
	RAnalFunction *fcn = r_anal_create_function (anal, "m", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create_function");

	bool ok = r_anal_function_set_vm_args (fcn, "v", 3, 3);
	mu_assert ("vm args applied", ok);

	RAnalVar *v3 = r_anal_function_get_var_byname (fcn, "v3");
	RAnalVar *v4 = r_anal_function_get_var_byname (fcn, "v4");
	RAnalVar *v5 = r_anal_function_get_var_byname (fcn, "v5");
	mu_assert_notnull (v3, "var v3");
	mu_assert_notnull (v4, "var v4");
	mu_assert_notnull (v5, "var v5");
	mu_assert_eq (v3->kind, R_ANAL_VAR_KIND_REG, "v3 is REG-kind");
	mu_assert ("v3 isarg", v3->isarg);
	mu_assert_eq (v3->delta, 3, "v3 delta");
	mu_assert_eq (v4->delta, 4, "v4 delta");
	mu_assert_eq (v5->delta, 5, "v5 delta");

	r_anal_free (anal);
	mu_end;
}

// JVM-shaped profile: l0 isn't at delta 0, so the helper must look up
// "l<first+i>" by name rather than assuming delta == bytecode index.
static bool test_vm_args_jvm(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new");
	load_jvm_profile (anal);
	RAnalFunction *fcn = r_anal_create_function (anal, "M", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create_function");

	RRegItem *l0 = r_reg_get (anal->reg, "l0", -1);
	mu_assert_notnull (l0, "l0 register exists");
	const int l0_idx = l0->index;
	r_unref (l0);
	mu_assert ("l0 not at delta 0", l0_idx != 0);

	bool ok = r_anal_function_set_vm_args (fcn, "l", 0, 4);
	mu_assert ("vm args applied", ok);

	int i;
	for (i = 0; i < 4; i++) {
		char nm[8];
		snprintf (nm, sizeof (nm), "l%d", i);
		RAnalVar *var = r_anal_function_get_var_byname (fcn, nm);
		mu_assert_notnull (var, "var present");
		mu_assert_eq (var->kind, R_ANAL_VAR_KIND_REG, "REG-kind");
		mu_assert ("isarg", var->isarg);
		mu_assert_eq (var->delta, l0_idx + i, "delta tracks reg-profile index");
	}

	r_anal_free (anal);
	mu_end;
}

// Edge cases: bad inputs must not create anything and must report false.
static bool test_vm_args_edges(void) {
	RAnal *anal = r_anal_new ();
	load_dalvik_profile (anal);
	RAnalFunction *fcn = r_anal_create_function (anal, "m", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);

	mu_assert ("count 0 is no-op", !r_anal_function_set_vm_args (fcn, "v", 0, 0));
	mu_assert ("NULL prefix is no-op", !r_anal_function_set_vm_args (fcn, NULL, 0, 1));
	mu_assert ("negative count is no-op", !r_anal_function_set_vm_args (fcn, "v", 0, -3));
	// Asking for a register that doesn't exist in the profile must be a no-op
	mu_assert ("unknown reg is no-op", !r_anal_function_set_vm_args (fcn, "v", 9999, 1));
	mu_assert_null (r_anal_function_get_var_byname (fcn, "v9999"), "no var for unknown reg");

	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_vm_args_dalvik);
	mu_run_test (test_vm_args_jvm);
	mu_run_test (test_vm_args_edges);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
