#include <r_core.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_sys_clearenv ();
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (!len) {
		return 0;
	}
	RCore *core = r_core_new ();
	if (!core) {
		return 0;
	}
	r_core_cmd0 (core, "e cfg.sandbox=true");
	r_core_cmd0 (core, "e scr.interactive=false");
	r_core_cmd0 (core, "e scr.color=0");
	r_core_cmdf (core, "o malloc://%" PFMT64d, (ut64)len);
	r_io_write_at (core->io, 0, data, len);
	r_core_cmd0 (core, "oob");
	r_core_cmd0 (core, "oba 0");
	r_core_cmd0 (core, "ia");
	r_core_cmd0 (core, "iaj");
	r_core_cmd0 (core, "ii");
	r_core_cmd0 (core, "is");
	r_core_cmd0 (core, "il");
	r_core_cmd0 (core, "ie");
	r_core_free (core);
	return 0;
}
