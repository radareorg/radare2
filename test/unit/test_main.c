#include <r_core.h>
#include <r_main.h>
#include "minunit.h"

bool test_main_borrowed_console(void) {
	RCore *core = r_core_new ();
	RCons *cons = core->cons;
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.interactive", false);
	char *previous_cons = r_sys_getenv ("R2CONS");
	r_strf_var (cons_ptr, 64, "%p", cons);
	r_sys_setenv ("R2CONS", cons_ptr);
	const char *argv[] = { "rax2", "33", NULL };
	mu_assert_eq (r_main_rax2 (2, argv), 0, "R2CONS console succeeds");
	mu_assert_streq (r_cons_get_buffer (cons, NULL), "0x21\n", "borrowed console captures output");
	r_cons_reset (cons);
	char *value = r_sys_getenv ("R2CONS");
	mu_assert_streq_free (value, cons_ptr, "tool preserves console environment");

	const RMainCallback callbacks[] = {
		r_main_rasm2, r_main_rax2, r_main_rabin2, r_main_radiff2,
		r_main_rafind2, r_main_rahash2, r_main_ragg2, r_main_rapatch2,
		r_main_rafs2, r_main_ravc2, r_main_rarun2, r_main_rasign2,
		r_main_r2pm, r_main_r2agent, r_main_radare2
	};
	const char *help[] = { "tool", "-h", NULL };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (callbacks); i++) {
		callbacks[i] (2, help);
		size_t len = 0;
		r_cons_get_buffer (cons, &len);
		mu_assert ("help captured in borrowed console", len > 0);
		mu_assert_ptreq (r_cons_global (NULL), cons, "tool preserves active console");
		mu_assert_ptreq (cons->user, core, "tool preserves caller callbacks");
		mu_assert_ptreq (cons->num, core->num, "tool preserves caller numeric state");
		r_cons_reset (cons);
	}
	r_sys_setenv ("R2CONS", NULL);
	mu_assert_eq (r_main_rax2 (2, argv), 0, "standalone output succeeds");
	size_t len = 0;
	r_cons_get_buffer (cons, &len);
	mu_assert_eq (len, 0, "absent R2CONS does not fall back to R2CORE");
	mu_assert_null (r_sys_getenv ("R2CONS"), "tool restores absent environment variable");
	r_sys_setenv ("R2CONS", previous_cons);
	free (previous_cons);
	r_core_free (core);
	mu_assert_false (r_cons_is_initialized (), "no tool-owned console left alive");
	mu_end;
}

bool test_main_shell_capture(void) {
	RCore *core = r_core_new ();
	core->r_main_rasm2 = r_main_rasm2;
	core->r_main_radare2 = r_main_radare2;
	core->r_main_radiff2 = r_main_radiff2;
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.interactive", false);
	char *previous_cons = r_sys_getenv ("R2CONS");
	r_sys_setenv ("R2CONS", "saved-value");
	char *output = r_core_cmd_str (core, "echo before; rasm2 -a x86 -d 90; echo after");
	mu_assert_streq_free (output, "before\nnop\nafter\n", "shell output order and capture");
	output = r_sys_getenv ("R2CONS");
	mu_assert_streq_free (output, "saved-value", "shell restores previous environment");
	output = r_core_cmd_str (core, "r2 -NNQ -c 'echo inner; rasm2 -a x86 -d c3' --; echo outer");
	mu_assert_streq_free (output, "inner\nret\nouter\n", "nested main returns to caller");
	int i;
	for (i = 0; i < 2; i++) {
		output = r_core_cmd_str (core, "radiff2 -h");
		mu_assert_notnull (strstr (output, "Usage: radiff2"), "repeated tool help is captured");
		free (output);
	}
	output = r_core_cmd_str (core, "echo alive");
	mu_assert_streq_free (output, "alive\n", "repeated tool calls preserve console");
	mu_assert_ptreq (core->cons->user, core, "nested core preserves caller callbacks");
	mu_assert_ptreq (core->cons->num, core->num, "nested core preserves caller numeric state");
	r_sys_setenv ("R2CONS", previous_cons);
	free (previous_cons);
	r_core_free (core);
	mu_end;
}

bool test_main_binary_capture(void) {
	RCore *core = r_core_new ();
	char *previous_cons = r_sys_getenv ("R2CONS");
	r_strf_var (cons_ptr, 64, "%p", core->cons);
	r_sys_setenv ("R2CONS", cons_ptr);
	const char *argv[] = { "rax2", "-s", "410042", NULL };
	mu_assert_eq (r_main_rax2 (3, argv), 0, "binary output succeeds");
	size_t len;
	const char *output = r_cons_get_buffer (core->cons, &len);
	mu_assert_eq (len, 3, "binary output length");
	mu_assert_memeq ((const ut8 *)output, (const ut8 *)"A\0B", 3, "binary output preserves embedded NUL");
	r_sys_setenv ("R2CONS", previous_cons);
	free (previous_cons);
	r_core_free (core);
	mu_end;
}

bool test_main_child_console(void) {
	RCore *core = r_core_new ();
	RCons *child = r_cons_new_child (core->cons);
	char *previous_cons = r_sys_getenv ("R2CONS");
	r_strf_var (cons_ptr, 64, "%p", child);
	r_sys_setenv ("R2CONS", cons_ptr);
	const char *argv[] = { "rax2", "33", NULL };
	mu_assert_eq (r_main_rax2 (2, argv), 0, "use an unattached child console");
	mu_assert_streq (r_cons_get_buffer (child, NULL), "0x21\n", "plain pointer captures output in child console");
	mu_assert_ptreq (r_cons_global (NULL), core->cons, "restore original active console");
	mu_assert_true (child->context->noflush, "preserve capture mode");
	r_sys_setenv ("R2CONS", previous_cons);
	free (previous_cons);
	r_cons_free (child);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_main_borrowed_console);
	mu_run_test (test_main_shell_capture);
	mu_run_test (test_main_binary_capture);
	mu_run_test (test_main_child_console);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
