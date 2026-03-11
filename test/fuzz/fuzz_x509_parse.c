#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_asn1.h>
#include <r_util/r_log.h>
#include <r_util/r_x509.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

static void fuzz_x509_certificate(const ut8 *buffer, ut32 length) {
	RASN1Object *object = r_asn1_object_parse (buffer, buffer, length, 0);
	if (!object) {
		return;
	}
	RX509Certificate *certificate = r_x509_certificate_parse (object);
	if (!certificate) {
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	char *text = NULL;
	if (sb) {
		r_x509_certificate_dump (certificate, "", sb);
		text = r_strbuf_drain (sb);
	}
	PJ *pj = pj_new ();
	if (pj) {
		r_x509_certificate_json (pj, certificate);
		free (pj_drain (pj));
	}
	free (text);
	r_x509_certificate_free (certificate);
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (!len) {
		return 0;
	}
	fuzz_x509_certificate (data, (ut32)len);
	return 0;
}
