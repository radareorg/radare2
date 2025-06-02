/* radare - LGPL - Copyright 2017-2025 - Sylvain Pelissier
 * Implementation of SM4 block cipher
 * https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
 * */

#include <r_muta/r_sm4.h>
#include <r_muta.h>
#include <memory.h>

static void sm4_crypt(const ut32 *sk, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	for (; buflen > 0; buflen -= SM4_BLOCK_SIZE) {
		sm4_round (sk, inbuf, outbuf);
		inbuf += SM4_BLOCK_SIZE;
		outbuf += SM4_BLOCK_SIZE;
	}
}

static bool sm4_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->dir = direction;
	return sm4_init (cj->sm4_sk, key, keylen, direction);
}

static int sm4_get_key_size(RMutaSession *cry) {
	return SM4_KEY_SIZE;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj&& buf, false);
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	/* SM4 encryption or decryption */
	sm4_crypt (cj->sm4_sk, buf, obuf, len);
	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return true;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_sm4 = {
	.type = R_CRYPTO_TYPE_ENCRYPT,
	.meta = {
		.name = "sm4-ecb",
		.desc = "ShāngMì4 block cipher with Electronic Code Book mode",
		.author = "Sylvain Pelissier",
		.license = "LGPL-3.0-only",
	},
	.implements = "sm4-ecb",
	.set_key = sm4_set_key,
	.get_key_size = sm4_get_key_size,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_sm4,
	.version = R2_VERSION
};
#endif
