/* radare - LGPL - Copyright 2015-2016 - pancake */

#include <r_lib.h>
#include <r_crypto.h>
#include "crypto_aes_algo.h"

static struct aes_state st;
static int flag = 0;

static int aes_set_key (RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	st.key_size = keylen;
	st.rounds = 6 + (int)(keylen / 4);
	st.columns = (int)(keylen / 4);
	memcpy(st.key, key, keylen);
	flag = direction;

	// printf("*** State:\n
	//         Key: %s\n
	//         Received keylen: %d\t\tkey_size: %d\n
	//         columns: %d\n
	//         rounds: %d\n
	//         Finished!\n", st.key, keylen, st.key_size, st.columns, st.rounds);
	return true;
}

static int aes_get_key_size (RCrypto *cry) {
	return st.key_size;
}

static bool aes_use (const char *algo) {
	return !strcmp (algo, "aes-ecb");
}

#define BLOCK_SIZE 16

static int update (RCrypto *cry, const ut8 *buf, int len) {
	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;

	ut8 *const obuf = calloc (1, size);
	if (!obuf) return false;

	ut8 *const ibuf = calloc (1, size);
	if (!ibuf) {
		free (obuf);
		return false;
	}

	memset(ibuf, 0, size);
	memcpy (ibuf, buf, len);
	// Padding should start like 100000...
	if (diff) {
		ibuf[len] = 8; //0b1000;
	}

	// printf("*** State:\n
	//         Key: %s\n
	//         key_size: %d\n
	//         columns: %d\n
	//         rounds: %d\n", st.key, st.key_size, st.columns, st.rounds);
	int i;
	if (flag == 0) {
		for (i = 0; i < blocks; i++) {
			// printf("Block: %d\n", i);
			aes_encrypt (&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			// printf("Block finished: %d\n", i);
		}
	} else if (flag == 1) {
		for (i = 0; i < blocks; i++) {
			aes_decrypt (&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
		}
	}

	// printf("%128s\n", obuf);

	r_crypto_append (cry, obuf, size);
	free (obuf);
	free (ibuf);
	return 0;
}

static int final (RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_aes = { 
	.name = "aes-ecb",
	.set_key = aes_set_key,
	.get_key_size = aes_get_key_size,
	.use = aes_use,
	.update = update,
	.final = final
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = { 
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_aes,
	.version = R2_VERSION
};
#endif

