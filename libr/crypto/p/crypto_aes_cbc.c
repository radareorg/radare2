/* radare - LGPL - Copyright 2016-2024 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_util/r_log.h>
#include <r_util/r_assert.h>
#include <r_crypto.h>
#include "crypto_aes_algo.h"

static bool aes_cbc_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	cj->key_len = keylen;
	memcpy (cj->key, key, keylen);
	cj->dir = direction;
	return true;
}

static int aes_cbc_get_key_size(RCryptoJob *cj) {
	R_RETURN_VAL_IF_FAIL (cj, -1);
	return cj->key_len;
}

static bool aes_cbc_set_iv(RCryptoJob *cj, const ut8 *iv_src, int ivlen) {
	if (ivlen != AES_BLOCK_SIZE) {
		return false;
	}
	cj->iv = calloc (1, AES_BLOCK_SIZE);
	if (!cj->iv) {
		return false;
	}
	memcpy (cj->iv, iv_src, AES_BLOCK_SIZE);
	return true;
}

static bool aes_cbc_check(const char *algo) {
	return algo && !strcmp (algo, "aes-cbc");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	if (!cj->iv) {
		R_LOG_ERROR ("AES CBC IV is not defined");
		return false;
	}

	if (len % AES_BLOCK_SIZE != 0 && cj->dir == R_CRYPTO_DIR_DECRYPT) {
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

	st.key_size = cj->key_len;
	st.rounds = 6 + (int)(st.key_size / 4);
	st.columns = (int)(st.key_size / 4);
	memcpy (st.key, cj->key, st.key_size);

	if (aes_cbc (&st, ibuf, obuf, cj->iv, cj->dir == R_CRYPTO_DIR_ENCRYPT, blocks)) {
		r_crypto_job_append (cj, obuf, size);
	}

	free (obuf);
	free (ibuf);
	return true;
}

RCryptoPlugin r_crypto_plugin_aes_cbc = {
	.type = R_CRYPTO_TYPE_ENCRYPT,
	.meta = {
		.name = "aes-cbc",
		.desc = "Rijndael block cipher with Cipher Block Chaining mode",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.set_key = aes_cbc_set_key,
	.get_key_size = aes_cbc_get_key_size,
	.set_iv = aes_cbc_set_iv,
	.check = aes_cbc_check,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_aes_cbc,
	.version = R2_VERSION
};
#endif
