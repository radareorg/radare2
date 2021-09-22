/* radare - LGPL - Copyright 2021 - Sylvain Pelissier 
   Implementation of AES Key Wrap Algorithm (RFC 3394) */

#include <r_lib.h>
#include <r_crypto.h>
#include "crypto_aes_algo.h"

#define BLOCK_SIZE 8

static struct aes_state st;
static bool iv_set = 0;
static ut8 iv[8];

static bool aes_wrap_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	st.key_size = keylen;
	st.rounds = 6 + (int)(keylen / 4);
	st.columns = (int)(keylen / 4);
	memcpy (st.key, key, keylen);
	cry->dir = direction;
	return true;
}

static int aes_wrap_get_key_size(RCrypto *cry) {
	return st.key_size;
}

static bool aes_wrap_set_iv(RCrypto *cry, const ut8 *iv_src, int ivlen) {
	if (ivlen != BLOCK_SIZE) {
		return false;
	} else {
		memcpy (iv, iv_src, BLOCK_SIZE);
	}
	iv_set = 1;
	return true;
}

static bool aes_wrap_use(const char *algo) {
	return algo && !strcmp (algo, "aes-wrap");
}

static bool update(RCrypto *cry, const ut8 *buf, int len) {
	ut64 blocks = len / BLOCK_SIZE;
	static ut8 tmp[16];
	long *tmp_ptr =  (long *)tmp;
	ut64 t=0;
	int i, j;

	if (len % BLOCK_SIZE != 0) {
		eprintf ("Length must be a multiple of %d.\n", BLOCK_SIZE);
		return false;
	}

	if (len < 16 && cry->dir == 0) {
		eprintf ("Length must be at least 16.\n");
		return false;
	} else if (len < 24 && cry->dir == 1)
	{
		eprintf ("Length must be at least 24.\n");
		return false;
	}

	ut8 *const obuf = calloc (1, len + BLOCK_SIZE);
	if (!obuf) {
		return false;
	}
	long *obuf_ptr = (long *)obuf;
	
	if (!iv_set) {
		memset (iv, 0xa6, 8);
	}

	if (cry->dir == 0) {
		// Encrypt
		memcpy (obuf, iv, BLOCK_SIZE);
		memcpy (obuf+8, buf, len);
		for (j = 0; j <= 5; j++) {
			for (i = 0; i < blocks; i++) {
				/* B = AES(K, A | R[i]) */
				*tmp_ptr = *obuf_ptr;
				*(tmp_ptr+1) = *(obuf_ptr+i+1);
				aes_encrypt (&st, tmp, tmp);

				/* A = MSB(64, B) ^ t */
				t++;
				t = r_swap_ut64 (t);
				*obuf_ptr =  t ^ *tmp_ptr;
				t = r_swap_ut64 (t);

				/* R[i] = LSB(64, B) */
				*(obuf_ptr+i+1) = *(tmp_ptr+1);
			}
		}
		r_crypto_append (cry, obuf, len + BLOCK_SIZE);
	} else if (cry->dir == 1) {
		// Decrypt
		blocks -= 1;
		t = 6 * blocks;
		memcpy (obuf, buf, len);
		for (j = 0; j <= 5; j++) {
      		for (i = blocks; i >= 1; i--) {
				/* B = AES^-1( (A ^ t)| R[i] ) */
				t = r_swap_ut64 (t);
				*tmp_ptr =  t ^ *obuf_ptr;
				t = r_swap_ut64 (t);
				t--;
				*(tmp_ptr+1) = *(obuf_ptr+i);
				aes_decrypt (&st, tmp, tmp);
				
				/* A = MSB_64(B) */
				*obuf_ptr = *tmp_ptr;
				/* R[i] = LSB_64(B) */
				*(obuf_ptr+i) = *(tmp_ptr+1);
        	}
   		}
		if (memcmp(iv, obuf,8)){
			eprintf ("Invalid integrity check\n");
			return false;
		}
		r_crypto_append (cry, obuf+BLOCK_SIZE, len-BLOCK_SIZE);
	}
	
	free (obuf);
	return true;
}

static bool final(RCrypto *cry, const ut8 *buf, int len) {
	return true;
}

RCryptoPlugin r_crypto_plugin_aes_wrap = {
	.name = "aes-wrap",
	.set_key = aes_wrap_set_key,
	.get_key_size = aes_wrap_get_key_size,
	.set_iv = aes_wrap_set_iv,
	.use = aes_wrap_use,
	.update = update,
	.final = final
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_aes_wrap,
	.version = R2_VERSION
};
#endif
