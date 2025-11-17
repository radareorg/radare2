#include <r_types.h>
#include <r_util.h>
#include <r_anal.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (len < 1) {
		return 0;
	}

	// Ensure null-terminated string for the parser
	char *input = r_str_ndup ((const char *)data, len);
	if (!input) {
		return 0;
	}

	char *errmsg = NULL;
	char *result = r_anal_cparse2 (NULL, (const char *)input, &errmsg);

	// Clean up
	free (input);
	free (result);
	free (errmsg);

	return 0;
}