/* radare - LGPL - Copyright 2021-2025 - Sylvain Pelissier
 * Implementation of AES Key Wrap Algorithm (RFC 3394) */

#include <r_lib.h>
#include <r_muta.h>
#include <r_util/r_log.h>
#include "algo/crypto_aes.h"

static bool aes_wrap_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	if (! (keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	ms->key_len = keylen;
	memcpy (ms->key, key, keylen);
	ms->dir = direction;
	return true;
}

static int aes_wrap_get_key_size(RMutaSession *ms) {
	return ms->key_len;
}

static bool aes_wrap_set_iv(RMutaSession *ms, const ut8 *iv_src, int ivlen) {
	if (ivlen != AES_WRAP_BLOCK_SIZE) {
		return false;
	}
	ms->iv = malloc (AES_WRAP_BLOCK_SIZE);
	if (ms->iv) {
		memcpy (ms->iv, iv_src, AES_WRAP_BLOCK_SIZE);
	}
	return true;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	struct aes_state st;
	const ut64 blocks = len / AES_WRAP_BLOCK_SIZE;

	if (len % AES_WRAP_BLOCK_SIZE != 0) {
		R_LOG_ERROR ("Length must be a multiple of %d", AES_WRAP_BLOCK_SIZE);
		return false;
	}

	if (len < 16 && ms->dir == R_MUTA_OP_ENCRYPT) {
		R_LOG_ERROR ("Length must be at least 16");
		return false;
	}

	if (len < 24 && ms->dir == R_MUTA_OP_DECRYPT) {
		R_LOG_ERROR ("Length must be at least 24");
		return false;
	}

	ut8 *const obuf = calloc (1, len + AES_WRAP_BLOCK_SIZE);
	if (!obuf) {
		return false;
	}

	if (!ms->iv) {
		ms->iv = malloc (AES_WRAP_BLOCK_SIZE);
		memset (ms->iv, 0xa6, AES_WRAP_BLOCK_SIZE);
	}

	st.key_size = ms->key_len;
	st.rounds = 6 + (st.key_size / 4);
	st.columns = st.key_size / 4;
	memcpy (st.key, ms->key, st.key_size);

	bool ret = aes_wrap (&st, buf, obuf, ms->iv, ms->dir == R_MUTA_OP_ENCRYPT, blocks);
	if (ms->dir == R_MUTA_OP_ENCRYPT) {
		r_muta_session_append (ms, obuf, len + AES_WRAP_BLOCK_SIZE);
	} else {
		if (ret) {
			r_muta_session_append (ms, obuf, len - AES_WRAP_BLOCK_SIZE);
		}
	}

	free (obuf);
	return true;
}

static bool end(RMutaSession *ms, const ut8 *buf, int len) {
	return update (ms, buf, len);
}

RMutaPlugin r_muta_plugin_aes_wrap = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "aes-wrap",
		.desc = "Rijndael block cipher with Key Wrap Algorithm (RFC 3394)",
		.author = "Sylvain Pelissier",
		.license = "LGPL-3.0-only",
	},
	.implements = "aes-wrap",
	.set_key = aes_wrap_set_key,
	.get_key_size = aes_wrap_get_key_size,
	.set_iv = aes_wrap_set_iv,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_aes_wrap,
	.version = R2_VERSION
};
#endif
