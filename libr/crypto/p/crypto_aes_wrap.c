/* radare - LGPL - Copyright 2021-2022 - Sylvain Pelissier
 * Implementation of AES Key Wrap Algorithm (RFC 3394) */

#include <r_lib.h>
#include <r_crypto.h>
#include <r_util/r_log.h>
#include "crypto_aes_algo.h"


static bool aes_wrap_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	cj->key_len = keylen;
	memcpy (cj->key, key, keylen);
	cj->dir = direction;
	return true;
}

static int aes_wrap_get_key_size(RCryptoJob *cj) {
	return cj->key_len;
}

static bool aes_wrap_set_iv(RCryptoJob *cj, const ut8 *iv_src, int ivlen) {
	if (ivlen != AES_WRAP_BLOCK_SIZE) {
		return false;
	}
	cj->iv = malloc (AES_WRAP_BLOCK_SIZE);
	if (cj->iv) {
		memcpy (cj->iv, iv_src, AES_WRAP_BLOCK_SIZE);
	}
	return true;
}

static bool aes_wrap_use(const char *algo) {
	return algo && !strcmp (algo, "aes-wrap");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	struct aes_state st;
	ut64 blocks = len / AES_WRAP_BLOCK_SIZE;

	if (len % AES_WRAP_BLOCK_SIZE != 0) {
		R_LOG_ERROR ("Length must be a multiple of %d", AES_WRAP_BLOCK_SIZE);
		return false;
	}

	if (len < 16 && cj->dir == R_CRYPTO_DIR_ENCRYPT) {
		R_LOG_ERROR ("Length must be at least 16");
		return false;
	}

	if (len < 24 && cj->dir == R_CRYPTO_DIR_DECRYPT) {
		R_LOG_ERROR ("Length must be at least 24");
		return false;
	}

	ut8 *const obuf = calloc (1, len + AES_WRAP_BLOCK_SIZE);
	if (!obuf) {
		return false;
	}

	if (!cj->iv) {
		cj->iv = malloc (AES_WRAP_BLOCK_SIZE);
		if (cj->iv) {
			memset (cj->iv, 0xa6, AES_WRAP_BLOCK_SIZE);
		}
	}

	st.key_size = cj->key_len;
	st.rounds = 6 + (st.key_size / 4);
	st.columns = st.key_size / 4;
	memcpy (st.key, cj->key, st.key_size);

	bool ret = aes_wrap (&st, buf, obuf, cj->iv, cj->dir == R_CRYPTO_DIR_ENCRYPT, blocks);

	if (cj->dir == R_CRYPTO_DIR_ENCRYPT) {
		r_crypto_job_append (cj, obuf, len + AES_WRAP_BLOCK_SIZE);
	} else {
		if (ret) {
			r_crypto_job_append (cj, obuf, len - AES_WRAP_BLOCK_SIZE);
		}
	}

	free (obuf);
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RCryptoPlugin r_crypto_plugin_aes_wrap = {
	.type = R_CRYPTO_TYPE_ENCRYPT,
	.meta = {
		.name = "aes-wrap",
		.desc = "Rijndael block cipher with Key Wrap Algorithm (RFC 3394)",
		.author = "Sylvain Pelissier",
		.license = "LGPL-3.0-only",
	},
	.set_key = aes_wrap_set_key,
	.get_key_size = aes_wrap_get_key_size,
	.set_iv = aes_wrap_set_iv,
	.check = aes_wrap_use,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_aes_wrap,
	.version = R2_VERSION
};
#endif
