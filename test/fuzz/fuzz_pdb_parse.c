#include <r_types.h>
#include <r_util/r_log.h>
#include <r_pdb.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RBuffer *buf = r_buf_new_with_bytes (data, len);

	RPdb pdb = { 0 };
	if (r_bin_pdb_parser_with_buf (&pdb, buf)) {
		pdb.pdb_parse (&pdb);
		pdb.finish_pdb_parse (&pdb);
	} else {
		free (buf);
	}

	return 0;
}
