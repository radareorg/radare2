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

static bool sm4_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	ms->dir = direction;
	return sm4_init (ms->sm4_sk, key, keylen, direction);
}

static int sm4_get_key_size(RMutaSession *cry) {
	return SM4_KEY_SIZE;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	if (len < 1) {
		return false;
	}
	const int tail = len % SM4_BLOCK_SIZE;
	if (tail && ms->dir == R_MUTA_OP_DECRYPT) {
		R_LOG_ERROR ("Length must be a multiple of %d for decryption", SM4_BLOCK_SIZE);
		return false;
	}
	// encryption zero pads the last partial block
	const int size = len + (tail? SM4_BLOCK_SIZE - tail: 0);
	ut8 *obuf = calloc (1, size);
	if (!obuf) {
		return false;
	}
	sm4_crypt (ms->sm4_sk, buf, obuf, len - tail);
	if (tail) {
		ut8 last[SM4_BLOCK_SIZE] = {0};
		memcpy (last, buf + len - tail, tail);
		sm4_round (ms->sm4_sk, last, obuf + len - tail);
	}
	r_muta_session_append (ms, obuf, size);
	free (obuf);
	return true;
}

static bool end(RMutaSession *ms, const ut8 *buf, int len) {
	return update (ms, buf, len);
}

RMutaPlugin r_muta_plugin_sm4 = {
	.type = R_MUTA_TYPE_CRYPTO,
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
