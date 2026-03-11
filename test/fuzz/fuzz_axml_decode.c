#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_axml.h>
#include <r_util/r_log.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (!len) {
		return 0;
	}
	char *text = r_axml_decode (data, len, NULL);
	free (text);

	PJ *pj = pj_new ();
	if (pj) {
		text = r_axml_decode (data, len, pj);
		free (text);
		free (pj_drain (pj));
	}
	return 0;
}
