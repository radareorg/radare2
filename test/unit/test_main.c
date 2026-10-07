#include <r_core.h>
#include <r_main.h>
#include "minunit.h"

bool test_main_borrowed_console(void) {
	RCore *core = r_core_new ();
	RCons *cons = core->cons;
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.interactive", false);
	const char *argv[] = { "rax2", "33", NULL };
	mu_assert_eq (r_main_rax2 (cons, 2, argv), 0, "borrowed console succeeds");
	mu_assert_streq (r_cons_get_buffer (cons, NULL), "0x21\n", "borrowed console captures output");
	r_cons_reset (cons);

	const RMainCallback callbacks[] = {
		r_main_rasm2, r_main_rax2, r_main_rabin2, r_main_radiff2,
		r_main_rafind2, r_main_rahash2, r_main_ragg2, r_main_rapatch2,
		r_main_rafs2, r_main_ravc2, r_main_rarun2, r_main_rasign2,
		r_main_r2pm, r_main_r2agent, r_main_radare2
	};
	const char *help[] = { "tool", "-h", NULL };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (callbacks); i++) {
		callbacks[i] (cons, 2, help);
		size_t len = 0;
		r_cons_get_buffer (cons, &len);
		mu_assert ("help captured in borrowed console", len > 0);
		mu_assert_ptreq (r_cons_global (NULL), cons, "tool preserves active console");
		mu_assert_ptreq (cons->user, core, "tool preserves caller callbacks");
		mu_assert_ptreq (cons->num, core->num, "tool preserves caller numeric state");
		r_cons_reset (cons);
	}
	mu_assert_eq (r_main_rax2 (NULL, 2, argv), 0, "standalone output succeeds");
	size_t len = 0;
	r_cons_get_buffer (cons, &len);
	mu_assert_eq (len, 0, "standalone output leaves caller buffer alone");
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
	RCons *other = r_cons_new ();
	char *output = r_core_cmd_str (core, "echo before; rasm2 -a x86 -d 90; echo after");
	mu_assert_streq_free (output, "before\nnop\nafter\n", "shell output order and capture");
	mu_assert_ptreq (r_cons_global (NULL), other, "shell restores previous active console");
	output = r_core_cmd_str (core, "r2 -NNQ -c 'echo inner; rasm2 -a x86 -d c3' --; echo outer");
	mu_assert_streq_free (output, "inner\nret\nouter\n", "nested main returns to caller");
	mu_assert_ptreq (r_cons_global (NULL), other, "nested tools restore previous active console");
	output = r_core_cmd_str (core, "radiff2 bins/other/radiff2/radiff2_c_1 bins/other/radiff2/radiff2_c_2");
	mu_assert_streq_free (output, "0x00000000 91 => 90 0x00000000\n", "diff callback uses the caller console");
	size_t i;
	for (i = 0; i < 2; i++) {
		output = r_core_cmd_str (core, "radiff2 -h");
		mu_assert_notnull (strstr (output, "Usage: radiff2"), "repeated tool help is captured");
		free (output);
	}
	output = r_core_cmd_str (core, "echo alive");
	mu_assert_streq_free (output, "alive\n", "repeated tool calls preserve console");
	mu_assert_ptreq (core->cons->user, core, "nested core preserves caller callbacks");
	mu_assert_ptreq (core->cons->num, core->num, "nested core preserves caller numeric state");
	core->r_main_rasm2 = NULL;
	output = r_core_cmd_str (core, "rasm2 -h");
	free (output);
	mu_assert_eq (core->num->value, 1, "missing tool reports failure");
	mu_assert_ptreq (r_cons_global (NULL), other, "missing tool preserves alternate console");
	r_cons_free (other);
	r_core_free (core);
	mu_end;
}

bool test_main_binary_capture(void) {
	RCore *core = r_core_new ();
	const char *argv[] = { "rax2", "-s", "410042", NULL };
	mu_assert_eq (r_main_rax2 (core->cons, 3, argv), 0, "binary output succeeds");
	size_t len;
	const char *output = r_cons_get_buffer (core->cons, &len);
	mu_assert_eq (len, 3, "binary output length");
	mu_assert_memeq ((const ut8 *)output, (const ut8 *)"A\0B", 3, "binary output preserves embedded NUL");
	r_cons_reset (core->cons);
	const char *diff_argv[] = { "radiff2", "-f1", "bins/other/radiff2/radiff2_c_1", "bins/other/radiff2/radiff2_c_2", NULL };
	mu_assert_eq (r_main_radiff2 (core->cons, 4, diff_argv), 0, "binary diff output succeeds");
	output = r_cons_get_buffer (core->cons, &len);
	mu_assert_eq (len, 8, "binary diff output length");
	mu_assert_memeq ((const ut8 *)output, (const ut8 *)"\xd1\xff\xd1\xff\x04\x01\x90\0", 8, "diff callback captures binary bytes");
	r_core_free (core);
	mu_end;
}

bool test_main_child_console(void) {
	RCore *core = r_core_new ();
	RCons *child = r_cons_new_child (core->cons);
	const char *argv[] = { "rax2", "33", NULL };
	mu_assert_eq (r_main_rax2 (child, 2, argv), 0, "use an unattached child console");
	mu_assert_streq (r_cons_get_buffer (child, NULL), "0x21\n", "explicit console captures output in child console");
	mu_assert_ptreq (r_cons_global (NULL), core->cons, "restore original active console");
	mu_assert_true (child->context->noflush, "preserve capture mode");
	r_cons_reset (child);
	r_cons_bind (child, &core->bin->consb);
	r_bin_demangle_list (core->bin);
	size_t len = 0;
	r_cons_get_buffer (child, &len);
	mu_assert ("bin output uses its bound console", len > 0);
	r_cons_get_buffer (core->cons, &len);
	mu_assert_eq (len, 0, "bin output leaves the active console alone");
	r_cons_bind (core->cons, &core->bin->consb);
	r_cons_free (child);
	r_core_free (core);
	mu_end;
}

bool test_main_file_output(void) {
	RCore *core = r_core_new ();
	char *path = r_file_temp ("r2-main-output");
	const char *asm_argv[] = { "rasm2", "-a", "x86", "-B", "-o", path, "mov eax, 1", NULL };
	const char *egg_argv[] = { "ragg2", "-r", "-B", "410042", "-o", path, NULL };
	mu_assert_eq (r_main_rasm2 (core->cons, 7, asm_argv), 0, "assembly output file succeeds");
	size_t len;
	char *output = r_file_slurp (path, &len);
	mu_assert_eq (len, 5, "assembly file length");
	mu_assert_memeq ((ut8 *)output, (ut8 *)"\xb8\x01\0\0\0", 5, "assembly file preserves NUL bytes");
	free (output);
	mu_assert_eq (r_main_ragg2 (core->cons, 6, egg_argv), 0, "egg output file succeeds");
	output = r_file_slurp (path, &len);
	mu_assert_eq (len, 3, "egg file length");
	mu_assert_memeq ((ut8 *)output, (ut8 *)"A\0B", 3, "egg file preserves NUL bytes");
	free (output);
	mu_assert_ptreq (r_cons_global (NULL), core->cons, "file output preserves active console");
	r_cons_get_buffer (core->cons, &len);
	mu_assert_eq (len, 0, "file output leaves caller buffer empty");
	const char *find_argv[] = { "rafind2", "-x", "410042", path, NULL };
	mu_assert_eq (r_main_rafind2 (core->cons, 4, find_argv), 0, "search callback captures output");
	mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "0x0\n", "search uses its output context");
	r_cons_reset (core->cons);
	const char *argv[] = { "rax2", "33", NULL };
	mu_assert_eq (r_main_rax2 (core->cons, 2, argv), 0, "output after file tools succeeds");
	mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "0x21\n", "caller output remains usable");
	r_file_rm (path);
	free (path);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_main_borrowed_console);
	mu_run_test (test_main_shell_capture);
	mu_run_test (test_main_binary_capture);
	mu_run_test (test_main_child_console);
	mu_run_test (test_main_file_output);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
