/* radare - LGPL - Copyright 2016-2022 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_util/r_log.h>
#include <r_util/r_assert.h>
#include <r_crypto.h>
#include "crypto_aes_algo.h"

#define BLOCK_SIZE 16

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
	r_return_val_if_fail (cj, -1);
	return cj->key_len;
}

static bool aes_cbc_set_iv(RCryptoJob *cj, const ut8 *iv_src, int ivlen) {
	if (ivlen != BLOCK_SIZE) {
		return false;
	}
	cj->iv = calloc (1, BLOCK_SIZE);
	if (!cj->iv) {
		return false;
	}
	memcpy (cj->iv, iv_src, BLOCK_SIZE);
	return true;
}

static bool aes_cbc_check(const char *algo) {
	return algo && !strcmp (algo, "aes-cbc");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	if (!cj->iv) {
		R_LOG_ERROR ("AES CBC IV is not defined. Use rahash2 -I [iv]");
		return false;
	}
	struct aes_state st;
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;

	ut8 *const obuf = calloc (1, size);
	if (!obuf) {
		return false;
	}

	ut8 *const ibuf = calloc (1, size);
	if (!ibuf) {
		free (obuf);
		return false;
	}

	memset (ibuf, 0, size);
	memcpy (ibuf, buf, len);

	if (diff) {
		ibuf[len] = 8; // 0b1000;
	}

	st.key_size = cj->key_len;
	st.rounds = 6 + (int)(st.key_size / 4);
	st.columns = (int)(st.key_size / 4);
	memcpy (st.key, cj->key, st.key_size);

	int i, j;
	if (cj->dir == 0) {
		for (i = 0; i < blocks; i++) {
			for (j = 0; j < BLOCK_SIZE; j++) {
				ibuf[i * BLOCK_SIZE + j] ^= cj->iv[j];
			}
			aes_encrypt (&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			memcpy (cj->iv, obuf + BLOCK_SIZE * i, BLOCK_SIZE);
		}
	} else if (cj->dir == 1) {
		for (i = 0; i < blocks; i++) {
			aes_decrypt (&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			for (j = 0; j < BLOCK_SIZE; j++) {
				obuf[i * BLOCK_SIZE + j] ^= cj->iv[j];
			}
			memcpy (cj->iv, buf + BLOCK_SIZE * i, BLOCK_SIZE);
		}
	}

	r_crypto_job_append (cj, obuf, size);
	free (obuf);
	free (ibuf);
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RCryptoPlugin r_crypto_plugin_aes_cbc = {
	.name = "aes-cbc",
	.set_key = aes_cbc_set_key,
	.get_key_size = aes_cbc_get_key_size,
	.set_iv = aes_cbc_set_iv,
	.check = aes_cbc_check,
	.update = update,
	.end = end 
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_aes_cbc,
	.version = R2_VERSION
};
#endif
