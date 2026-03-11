#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_asn1.h>
#include <r_util/r_log.h>
#include <r_util/r_x509.h>
#include <r_util/r_pkcs7.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RCMS *cms = r_pkcs7_cms_parse (data, len);
	if (!cms) {
		return 0;
	}
	char *text = r_pkcs7_cms_tostring (cms);
	PJ *pj = r_pkcs7_cms_json (cms);
	SpcIndirectDataContent *spcinfo = r_pkcs7_spcinfo_parse (cms);

	free (text);
	if (pj) {
		free (pj_drain (pj));
	}
	r_pkcs7_spcinfo_free (spcinfo);
	r_pkcs7_cms_free (cms);
	return 0;
}
