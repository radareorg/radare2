#include <r_core.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	RCore *r = r_core_new();

	r_core_cmdf (r, "o malloc://%zu", Size);
	r_io_write_at (r->io, 0, Data, Size);

	char *cmd = r_str_ndup (Data, Size);
	r_core_cmd0 (r, cmd);
	free (cmd);

	r_core_free (r);
	return 0;
}
