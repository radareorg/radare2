#include <r_types.h>
#include <r_util/r_log.h>
#include <r_util/r_protobuf.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	char *pb = r_protobuf_decode (data, len, false);
	free (pb);
	return 0;
}
