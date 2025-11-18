#include <r_types.h>
#include <r_util/r_log.h>
#include <r_util/r_punycode.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	int dstlen;
	char *out = r_punycode_decode ((const char *)data, (int)len, &dstlen);
	free (out);
	return 0;
}
