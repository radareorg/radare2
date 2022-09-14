/* radare - LGPL - Copyright 2017-2022 - Sylvain Pelissier
 * Implementation of SM4 block cipher
 * https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
 *
 * */

#include "crypto_sm4_algo.h"
#include <r_lib.h>
#include <r_crypto.h>
#include <memory.h>

static bool sm4_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return sm4_init (sm4_sk, key, keylen, direction);
}

static int sm4_get_key_size(RCrypto *cry) {
	return SM4_KEY_SIZE;
}

static bool sm4_use(const char *algo) {
	return !strcmp (algo, "sm4-ecb");
}

static bool update(RCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf) {
		return false;
	}
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	/* SM4 encryption or decryption */
	sm4_crypt (sm4_sk, buf, obuf, len);
	r_crypto_append (cry, obuf, len);
	free (obuf);
	return true;
}

static bool final(RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_sm4 = {
	.name = "sm4-ecb",
	.license = "LGPL3",
	.set_key = sm4_set_key,
	.get_key_size = sm4_get_key_size,
	.use = sm4_use,
	.update = update,
	.final = final
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_sm4,
	.version = R2_VERSION
};
#endif
