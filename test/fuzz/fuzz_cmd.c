#include <r_core.h>

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_sys_clearenv ();
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RFuzzInput input;
	size_t bin_len = 0;
	size_t cmd_len = 0;
	ut64 io_len;
	if (!len) {
		return 0;
	}
	rfuzz_input_init (&input, data, len);
	const ut8 *bin_data = rfuzz_consume_bytes (&input, len, &bin_len);
	const ut8 *cmd_data = rfuzz_consume_tail (&input, &cmd_len);
	if (!bin_data || !bin_len) {
		bin_data = data;
		bin_len = len;
	}
	if (!cmd_data || !cmd_len) {
		cmd_data = data;
		cmd_len = len;
	}
	char *cmd = rfuzz_strndup (cmd_data, cmd_len);
	if (!cmd) {
		return 0;
	}
	rfuzz_normalize_text (cmd, cmd_len, '\n');

	RCore *core = r_core_new ();
	if (!core) {
		free (cmd);
		return 0;
	}
	r_core_cmd0 (core, "e cfg.sandbox=true");
	r_core_cmd0 (core, "e scr.interactive=false");
	r_core_cmd0 (core, "e scr.color=0");
	r_core_cmd0 (core, "e io.cache=true");
	io_len = bin_len? (ut64)bin_len: 1;
	r_core_cmdf (core, "o malloc://%" PFMT64d, io_len);
	r_io_write_at (core->io, 0, bin_data, bin_len);
	r_core_cmd0 (core, "oob");
	r_core_cmd0 (core, "s 0");
	r_core_cmd0 (core, "px 16");
	r_core_cmd_lines (core, cmd);
	r_core_free (core);
	free (cmd);
	r_sys_clearenv ();
	return 0;
}
