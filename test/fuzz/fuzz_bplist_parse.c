#include <r_types.h>
#include <r_util/bplist.h>
#include <r_util/pj.h>
#include <r_util/r_log.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	PJ *pj = pj_new ();
	if (!pj) {
		return 0;
	}
	r_bplist_parse (pj, data, len);
	free (pj_drain (pj));
	return 0;
}
