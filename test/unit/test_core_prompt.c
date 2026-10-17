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

#if R2__UNIX__ && HAVE_SIGACTION
bool test_core_signal_isolation(void) {
	struct sigaction before1, before2, current;
	sigaction (SIGUSR1, NULL, &before1);
	sigaction (SIGUSR2, NULL, &before2);
	RCore *core = r_core_new ();
	sigaction (SIGUSR1, NULL, &current);
	mu_assert_true (current.sa_handler == before1.sa_handler, "core creation preserves signals");
	mu_assert_true (r_core_signal_init (core), "install main signal handlers");
	r_config_set (core->config, "cmd.usr1", "f signal1=1");
	r_config_set (core->config, "cmd.usr2", "f signal2=2");
	RCore *temporary = r_core_new ();
	raise (SIGUSR1);
	raise (SIGUSR2);
	r_core_prompt_exec (temporary);
	mu_assert_null (r_flag_get (core->flags, "signal1"), "signal handler defers command execution");
	mu_assert_null (r_flag_get (temporary->flags, "signal1"), "temporary core cannot consume signals");
	r_core_free (temporary);
	r_core_prompt_exec (core);
	mu_assert_notnull (r_flag_get (core->flags, "signal1"), "SIGUSR1 reaches original core after temporary core teardown");
	mu_assert_notnull (r_flag_get (core->flags, "signal2"), "SIGUSR2 reaches original core");
	r_flag_unset_name (core->flags, "signal1");
	r_core_prompt_exec (core);
	mu_assert_null (r_flag_get (core->flags, "signal1"), "signal consumed once");
	raise (SIGUSR1);
	r_core_prompt_exec (core);
	mu_assert_notnull (r_flag_get (core->flags, "signal1"), "subsequent signal is handled");
	r_core_free (core);
	sigaction (SIGUSR1, NULL, &current);
	mu_assert_true (current.sa_handler == before1.sa_handler, "restore SIGUSR1 handler");
	sigaction (SIGUSR2, NULL, &current);
	mu_assert_true (current.sa_handler == before2.sa_handler, "restore SIGUSR2 handler");
	mu_end;
}
#endif

int all_tests(void) {
	mu_run_test (test_prompt_register_refs);
#if R2__UNIX__ && HAVE_SIGACTION
	mu_run_test (test_core_signal_isolation);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
