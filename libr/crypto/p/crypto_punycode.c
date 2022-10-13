/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_util.h>
#include <r_lib.h>
#include <r_crypto.h>

static bool punycode_set_key(RCryptoJob *ci, const ut8 *key, int keylen, int mode, int direction) {
	ci->flag = direction;
	return true;
}

static int punycode_get_key_size(RCryptoJob *cry) {
	return 0;
}

static bool punycode_check(const char *algo) {
	return !strcmp (algo, "punycode");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	char *obuf;
	int olen;
	if (cj->flag) {
		obuf = r_punycode_decode ((const char *)buf, len, &olen);
	} else {
		obuf = r_punycode_encode (buf, len, &olen);
	}
	r_crypto_job_append (cj, (ut8*)obuf, olen);
	free (obuf);
	return true;
}

RCryptoPlugin r_crypto_plugin_punycode = {
	.name = "punycode",
	.type = R_CRYPTO_TYPE_ENCODER,
	.set_key = punycode_set_key,
	.get_key_size = punycode_get_key_size,
	.check = punycode_check,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_punycode,
	.version = R2_VERSION
};
#endif
