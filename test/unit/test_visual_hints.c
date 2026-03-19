#include <r_core.h>
#include <r_anal.h>
#include "minunit.h"

static RCore *new_core_with_x86_bytes(ut64 addr, const ut8 *buf, int len) {
	RCore *core = r_core_new ();
	if (!core) {
		return NULL;
	}
	core->io->va = true;
	if (!r_io_open_at (core->io, "malloc://32", R_PERM_RW, 0644, addr)) {
		r_core_free (core);
		return NULL;
	}
	if (!r_io_write_at (core->io, addr, buf, len)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 32);
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "asm.hints", true);
	r_config_set_i (core->config, "asm.hint.pos", 0);
	r_core_seek (core, addr, true);
	r_core_block_size (core, 0x20);
	r_core_block_read (core);
	return core;
}

static void run_visual_pd(RCore *core) {
	char *out = NULL;
	core->vmode = true;
	out = r_core_cmd_str (core, "pd 1");
	free (out);
	core->vmode = false;
}

bool test_visual_hint_imm_push_uses_immediate_value(void) {
	const ut64 addr = 0x10014e9b;
	const ut8 buf[] = { 0x68, 0x9e, 0x4f, 0x01, 0x10 };
	RCore *core = new_core_with_x86_bytes (addr, buf, sizeof (buf));
	mu_assert_notnull (core, "Should create core");

	r_config_set_b (core->config, "asm.hint.call", false);
	r_config_set_b (core->config, "asm.hint.jmp", false);
	r_config_set_b (core->config, "asm.hint.lea", false);
	r_config_set_b (core->config, "asm.hint.emu", false);
	r_config_set_b (core->config, "asm.hint.imm", true);
	run_visual_pd (core);

	mu_assert_eq (r_core_get_asmqjmps (core, "1"), 0x10014f9e, "push imm shortcut should use the immediate value");

	r_core_free (core);
	mu_end;
}

bool test_visual_hint_lea_ignores_comment_metadata(void) {
	const ut64 addr = 0x10014e9b;
	const ut8 buf[] = { 0x68, 0x9e, 0x4f, 0x01, 0x10 };
	RCore *core = new_core_with_x86_bytes (addr, buf, sizeof (buf));
	mu_assert_notnull (core, "Should create core");

	r_config_set_b (core->config, "asm.hint.call", false);
	r_config_set_b (core->config, "asm.hint.jmp", false);
	r_config_set_b (core->config, "asm.hint.imm", false);
	r_config_set_b (core->config, "asm.hint.emu", false);
	r_config_set_b (core->config, "asm.hint.lea", true);
	r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, "comment");
	run_visual_pd (core);

	mu_assert_eq (r_core_get_asmqjmps (core, "1"), 0x10014f9e, "comment metadata must not replace the lea shortcut with instruction bytes");

	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_visual_hint_imm_push_uses_immediate_value);
	mu_run_test (test_visual_hint_lea_ignores_comment_metadata);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
