/* radare - LGPL - Copyright 2016-2025 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_util/r_log.h>
#include <r_util/r_assert.h>
#include <r_muta.h>
#include "algo/crypto_aes.h"

static bool aes_cbc_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	if (! (keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	ms->key_len = keylen;
	memcpy (ms->key, key, keylen);
	ms->dir = direction;
	return true;
}

static int aes_cbc_get_key_size(RMutaSession *ms) {
	R_RETURN_VAL_IF_FAIL (cj, -1);
	return ms->key_len;
}

static bool aes_cbc_set_iv(RMutaSession *ms, const ut8 *iv_src, int ivlen) {
	if (ivlen != AES_BLOCK_SIZE) {
		return false;
	}
	ms->iv = calloc (1, AES_BLOCK_SIZE);
	if (!ms->iv) {
		return false;
	}
	memcpy (ms->iv, iv_src, AES_BLOCK_SIZE);
	return true;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	if (!ms->iv) {
		R_LOG_ERROR ("AES CBC IV is not defined");
		return false;
	}

	if (len % AES_BLOCK_SIZE != 0 && ms->dir == R_MUTA_OPERATION_DECRYPT) {
		R_LOG_ERROR ("Length must be a multiple of %d for decryption", AES_BLOCK_SIZE);
		return false;
	}
	struct aes_state st;
	const int diff = (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / AES_BLOCK_SIZE;

	ut8 *const obuf = calloc (1, size);
	if (!obuf) {
		return false;
	}

	ut8 *const ibuf = calloc (1, size);
	if (!ibuf) {
		free (obuf);
		return false;
	}

	// Zero padding
	memset (ibuf, 0, size);
	memcpy (ibuf, buf, len);

	st.key_size = ms->key_len;
	st.rounds = 6 + (int) (st.key_size / 4);
	st.columns = (int) (st.key_size / 4);
	memcpy (st.key, ms->key, st.key_size);

	if (aes_cbc (&st, ibuf, obuf, ms->iv, ms->dir == R_MUTA_OPERATION_ENCRYPT, blocks)) {
		r_muta_session_append (cj, obuf, size);
	}

	free (obuf);
	free (ibuf);
	return true;
}

RMutaPlugin r_muta_plugin_aes_cbc = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "aes-cbc",
		.desc = "Rijndael block cipher with Cipher Block Chaining mode",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.implements = "aes-cbc",
	.set_key = aes_cbc_set_key,
	.get_key_size = aes_cbc_get_key_size,
	.set_iv = aes_cbc_set_iv,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_aes_cbc,
	.version = R2_VERSION
};
#endif
