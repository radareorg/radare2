/* radare - LGPL - Copyright 2016-2022 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

static bool base64_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->dir = direction;
	return true;
}

static int base64_get_key_size(RCryptoJob *cj) {
	return 0;
}

static bool base64_check(const char *algo) {
	return !strcmp (algo, "base64");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	if (cj->dir == 0) {
		olen = ((len + 2) / 3 ) * 4;
		obuf = malloc (olen + 1);
		if (!obuf) {
			return false;
		}
		r_base64_encode ((char *)obuf, (const ut8 *)buf, len);
	} else if (cj->dir == 1) {
		olen = 4 + ((len / 4) * 3);
		if (len > 0) {
			olen -= (buf[len-1] == '=') ? ((buf[len-2] == '=') ? 2 : 1) : 0;
		}
		obuf = malloc (olen + 4);
		if (!obuf) {
			return false;
		}
		olen = r_base64_decode (obuf, (const char *)buf, len);
	}
	if (olen > 0) {
		r_crypto_job_append (cj, obuf, olen);
	}
	free (obuf);
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RCryptoPlugin r_crypto_plugin_base64 = {
	.name = "base64",
   	.author = "rakholiyajenish.07",
	.type = R_CRYPTO_TYPE_ENCODER,
	.set_key = base64_set_key,
	.get_key_size = base64_get_key_size,
	.check = base64_check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_base64,
	.version = R2_VERSION
};
#endif
