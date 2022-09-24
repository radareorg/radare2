/* radare - LGPL - Copyright 2021-2022 - Sylvain Pelissier
 * Implementation of AES Key Wrap Algorithm (RFC 3394) */

#include <r_lib.h>
#include <r_crypto.h>
#include <r_util/r_log.h>
#include "crypto_aes_algo.h"

#define BLOCK_SIZE 8

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
	if (ivlen != BLOCK_SIZE) {
		return false;
	}
	cj->iv = malloc (BLOCK_SIZE);
	if (cj->iv) {
		memcpy (cj->iv, iv_src, BLOCK_SIZE);
	}
	return true;
}

static bool aes_wrap_use(const char *algo) {
	return algo && !strcmp (algo, "aes-wrap");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	struct aes_state st;
	ut64 blocks = len / BLOCK_SIZE;
	ut8 tmp[16] = {0};
	long *tmp_ptr = (long *)tmp;
	ut64 t = 0;
	int i, j;

	if (len % BLOCK_SIZE != 0) {
		R_LOG_ERROR ("Length must be a multiple of %d", BLOCK_SIZE);
		return false;
	}

	if (len < 16 && cj->dir == 0) {
		R_LOG_ERROR ("Length must be at least 16");
		return false;
	}

	if (len < 24 && cj->dir == 1) {
		R_LOG_ERROR ("Length must be at least 24");
		return false;
	}

	ut8 *const obuf = calloc (1, len + BLOCK_SIZE);
	if (!obuf) {
		return false;
	}
	long *obuf_ptr = (long *)obuf;

	if (!cj->iv) {
		cj->iv = malloc (BLOCK_SIZE);
		if (cj->iv) {
			memset (cj->iv, 0xa6, BLOCK_SIZE);
		}
	}

	st.key_size = cj->key_len;
	st.rounds = 6 + (st.key_size / 4);
	st.columns = st.key_size / 4;
	memcpy (st.key, cj->key, st.key_size);

	if (cj->dir == 0) {
		// Encrypt
		memcpy (obuf, cj->iv, BLOCK_SIZE);
		memcpy (obuf + BLOCK_SIZE, buf, len);
		for (j = 0; j <= 5; j++) {
			for (i = 0; i < blocks; i++) {
				/* B = AES(K, A | R[i]) */
				*tmp_ptr = *obuf_ptr;
				*(tmp_ptr + 1) = *(obuf_ptr + i + 1);
				aes_encrypt (&st, tmp, tmp);

				/* A = MSB(64, B) ^ t */
				t++;
				t = r_swap_ut64 (t);
				*obuf_ptr = t ^ *tmp_ptr;
				t = r_swap_ut64 (t);

				/* R[i] = LSB(64, B) */
				*(obuf_ptr + i + 1) = *(tmp_ptr + 1);
			}
		}
		r_crypto_job_append (cj, obuf, len + BLOCK_SIZE);
	} else if (cj->dir == 1) {
		// Decrypt
		blocks -= 1;
		t = 6 * blocks;
		memcpy (obuf, buf, len);
		for (j = 0; j <= 5; j++) {
			for (i = blocks; i >= 1; i--) {
				/* B = AES^-1( (A ^ t)| R[i] ) */
				t = r_swap_ut64 (t);
				*tmp_ptr = t ^ *obuf_ptr;
				t = r_swap_ut64 (t);
				t--;
				*(tmp_ptr + 1) = *(obuf_ptr + i);
				aes_decrypt (&st, tmp, tmp);

				/* A = MSB_64(B) */
				*obuf_ptr = *tmp_ptr;
				/* R[i] = LSB_64(B) */
				*(obuf_ptr + i) = *(tmp_ptr + 1);
			}
		}
		if (memcmp (cj->iv, obuf, BLOCK_SIZE)) {
			R_LOG_ERROR ("Invalid integrity check");
			return false;
		}
		r_crypto_job_append (cj, obuf + BLOCK_SIZE, len - BLOCK_SIZE);
	}

	free (obuf);
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RCryptoPlugin r_crypto_plugin_aes_wrap = {
	.name = "aes-wrap",
	.author = "Sylvain Pelissier",
	.license = "LGPL",
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
