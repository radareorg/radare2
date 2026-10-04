#include <r_core.h>
#include "minunit.h"

bool test_prompt_register_refs(void) {
	RCore *core = r_core_new ();
	core->print->wide_offsets = false;
	mu_assert_true (r_reg_set_profile_string (core->dbg->reg, "=PC eax\ngpr eax .32 0 0\n"), "register profile");
	mu_assert_true (r_reg_setv (core->dbg->reg, "eax", 0x1234), "register value");
	RRegItem *reg = r_reg_get (core->dbg->reg, "eax", -1);
	mu_assert_notnull (reg, "register");
	int refs = r_ref_count (reg);
	char *prompt = r_core_prompt_format (core, "${r:PC}/${r:eax}/${r:missing}");
	mu_assert_streq (prompt, "0x00001234/0x00001234/", "register placeholders");
	free (prompt);
	mu_assert_eq (r_ref_count (reg), refs, "prompt must release register references");
	r_unref (reg);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_prompt_register_refs);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
