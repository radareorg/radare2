#include <r_core.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	if (Size < 1) {
		return 0;
	}
	RCore *r = r_core_new ();
	if (Size < 1) {
		return 0;
	}

	r_core_cmd0 (r, "e scr.interactive=false");
	r_core_cmd0 (r, "e scr.color=0");
	// r_core_cmdf (r, "o malloc://%zu", Size);
	// r_io_write_at (r->io, 0, Data, Size);
	r_core_cmd0 (r, "o /bin/ls");
	r_core_cmd0 (r, "e cfg.sandbox=true");

	char *cmd = r_str_ndup ((const char *)Data, Size);
	if (cmd) {
		r_core_cmd_lines (r, cmd);
		free (cmd);
	}

	r_core_free (r);
	return 0;
}
