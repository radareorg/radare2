#include <r_types.h>
#include <r_util.h>
#include <r_anal.h>

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (len < 1) {
		return 0;
	}

	char *input = rfuzz_strndup (data, len);
	if (!input) {
		return 0;
	}
	rfuzz_normalize_text (input, len, ' ');

	RAnal *anal = r_anal_new ();
	char *errmsg = NULL;
	char *result = r_anal_cparse (anal, (const char *)input, &errmsg);
	if (anal && result) {
		r_anal_save_parsed_type (anal, result);
	}

	free (input);
	free (result);
	free (errmsg);
	r_anal_free (anal);

	return 0;
}
