#include <r_types.h>
#include <r_util/r_log.h>
#include <r_util/r_punycode.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	int encoded_len = 0;
	char *encoded = r_punycode_encode (data, (int)len, &encoded_len);
	if (encoded) {
		int decoded_len = 0;
		char *decoded = r_punycode_decode (encoded, encoded_len, &decoded_len);
		free (decoded);
	}
	free (encoded);

	int dstlen = 0;
	char *out = r_punycode_decode ((const char *)data, (int)len, &dstlen);
	if (out) {
		char *roundtrip = r_punycode_encode ((const ut8 *)out, dstlen, &encoded_len);
		free (roundtrip);
	}
	free (out);
	return 0;
}
