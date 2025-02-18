/* radare - LGPL - Copyright 2015-2022 - pancake */

#include <r_lib.h>
#include <r_crypto.h>
#include "crypto_aes_algo.h"

static bool aes_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	cj->key_len = keylen;
	memcpy (cj->key, key, keylen);
	cj->dir = direction;
	return true;
}

static int aes_get_key_size(RCryptoJob *cj) {
	return cj->key_len;
}

static bool aes_check(const char *algo) {
	return !strcmp (algo, "aes-ecb");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	struct aes_state st;

	if (len % AES_BLOCK_SIZE != 0 && cj->dir == R_CRYPTO_DIR_DECRYPT) {
		R_LOG_ERROR ("Length must be a multiple of %d for decryption", AES_BLOCK_SIZE);
		return false;
	}

	// Pad to the block size for encryption, do not append dummy block
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
	st.rounds = 6 + (st.key_size / 4);
	st.columns = (st.key_size / 4);
	memcpy (st.key, cj->key, st.key_size);

	if (aes_ecb (&st, ibuf, obuf, cj->dir == R_CRYPTO_DIR_ENCRYPT, blocks)) {
		r_crypto_job_append (cj, obuf, size);
	}

	free (obuf);
	free (ibuf);
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RCryptoPlugin r_crypto_plugin_aes = {
	.type = R_CRYPTO_TYPE_ENCRYPT,
	.meta = {
		.name = "aes-ecb",
		.desc = "Rijndael block cipher with Electronic Code Book mode",
		.author = "pancake",
		.license = "MIT",
	},
	.set_key = aes_set_key,
	.get_key_size = aes_get_key_size,
	.check = aes_check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_aes,
	.version = R2_VERSION
};
#endif

