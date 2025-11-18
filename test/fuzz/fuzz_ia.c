#include <stdio.h>
#include <r_core.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	RCore *r = r_core_new ();
	if (Size == 0) {
		return 0;
	}
	r_core_cmdf (r, "o malloc://%zu", Size);
	r_io_write_at (r->io, 0, Data, Size);

	r_core_cmd0 (r, "oba 0");
	r_core_cmd0 (r, "ia");
	r_core_cmd0 (r, "ii;is;il");

	r_core_free (r);
	return 0;
}
