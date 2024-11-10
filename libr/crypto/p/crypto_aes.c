/* radare - LGPL - Copyright 2015-2022 - pancake */

#include <r_lib.h>
#include <r_crypto.h>
#include "crypto_aes_algo.h"

#define BLOCK_SIZE 16

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
	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;
	int i;

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
	// Padding should start like 100000...
	if (diff) {
		ibuf[len] = 8; //0b1000;
	}

	st.key_size = cj->key_len;
	st.rounds = 6 + (st.key_size / 4);
	st.columns = (st.key_size / 4);
	memcpy (st.key, cj->key, st.key_size);

	if (cj->dir == R_CRYPTO_DIR_ENCRYPT) {
		for (i = 0; i < blocks; i++) {
			const int delta = BLOCK_SIZE * i;
			aes_encrypt (&st, ibuf + delta, obuf + delta);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			const int delta = BLOCK_SIZE * i;
			aes_decrypt (&st, ibuf + delta, obuf + delta);
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

