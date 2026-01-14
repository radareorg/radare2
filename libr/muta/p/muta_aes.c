/* radare - LGPL - Copyright 2015-2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include "algo/crypto_aes.h"

static bool aes_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	if (! (keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	ms->key_len = keylen;
	memcpy (ms->key, key, keylen);
	ms->dir = direction;
	return true;
}

static int aes_get_key_size(RMutaSession *ms) {
	return ms->key_len;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	struct aes_state st;

	if (len % AES_BLOCK_SIZE != 0 && ms->dir == R_MUTA_OP_DECRYPT) {
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

	st.key_size = ms->key_len;
	st.rounds = 6 + (st.key_size / 4);
	st.columns = (st.key_size / 4);
	memcpy (st.key, ms->key, st.key_size);

	if (aes_ecb (&st, ibuf, obuf, ms->dir == R_MUTA_OP_ENCRYPT, blocks)) {
		r_muta_session_append (ms, obuf, size);
	}

	free (obuf);
	free (ibuf);
	return true;
}

static bool end(RMutaSession *ms, const ut8 *buf, int len) {
	return update (ms, buf, len);
}

RMutaPlugin r_muta_plugin_aes = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "aes-ecb",
		.desc = "Rijndael block cipher with Electronic Code Book mode",
		.author = "pancake",
		.license = "MIT",
	},
	.implements = "aes-ecb",
	.set_key = aes_set_key,
	.get_key_size = aes_get_key_size,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_aes,
	.version = R2_VERSION
};
#endif
