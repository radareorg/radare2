#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_asn1.h>
#include <r_util/r_log.h>
#include <r_util/r_x509.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

R_API RX509Certificate *wtf_r_x509_parse_certificate2(const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return NULL;
	}
	RASN1Object *object = r_asn1_object_parse (buffer, buffer, length, 0);
	RX509Certificate *certificate = r_x509_certificate_parse (object);
	// object freed by r_x509_parse_certificate
	return certificate;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RX509Certificate *out = wtf_r_x509_parse_certificate2 (data, len);
	free (out);
	return 0;
}
