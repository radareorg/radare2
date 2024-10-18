/* radare - LGPL - Copyright 2009-2024 - pancake */

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
	char *obuf = NULL;
	int olen = 0;
	switch (cj->flag) {
	case R_CRYPTO_DIR_DECRYPT:
		obuf = r_punycode_decode ((const char *)buf, len, &olen);
		break;
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = r_punycode_encode (buf, len, &olen);
		break;
	}
	r_crypto_job_append (cj, (ut8*)obuf, olen);
	free (obuf);
	return true;
}

RCryptoPlugin r_crypto_plugin_punycode = {
	.meta = {
		.name = "punycode",
		.desc = "Unicoded represented in plain ascii",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
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
