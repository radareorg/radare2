#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_asn1.h>
#include <r_util/r_log.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

static void fuzz_asn1_mode(const ut8 *data, size_t len, int mode) {
	RAsn1 *asn1 = r_asn1_new (data, (int)len, mode);
	if (!asn1) {
		return;
	}
	char *oid = r_asn1_oid (asn1);
	char *text = r_asn1_tostring (asn1);
	free (oid);
	free (text);
	r_asn1_free (asn1);
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (!len) {
		return 0;
	}
	fuzz_asn1_mode (data, len, 0);
	fuzz_asn1_mode (data, len, 'j');
	return 0;
}
