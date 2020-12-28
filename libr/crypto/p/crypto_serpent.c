#include <r_lib.h>
#include <r_crypto.h>
#include "crypto_serpent_algo.h"

static struct serpent_state st = {{0}};

static bool serpent_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	eprintf ("key_size: %d\n", keylen);
	if ((keylen != 128 / 8) && (keylen != 192 / 8) && (keylen != 256 / 8)) {
		return false;
	}
	st.key_size = keylen * 8;
	eprintf ("key_size: %d\n", st.key_size);
	memcpy (st.key, key, keylen);
	cry->dir = direction;
	return true;
}

static int serpent_get_key_size(RCrypto *cry) {
	return st.key_size;
}

static bool serpent_use(const char *algo) {
	return !strcmp (algo, "serpent-ecb");
}

#define BLOCK_SIZE 16

static bool update(RCrypto *cry, const ut8 *buf, int len) {
	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;
	int i, j;

	ut8 *const obuf = calloc (4, size / 4);
	if (!obuf) {
		return false;
	}
	ut32 *const ibuf = calloc (4, size / 4);
	if (!ibuf) {
		free (obuf);
		return false;
	}
	ut32 *const tmp = calloc (4, size / 4);
	if (!tmp) {
		free (obuf);
		free (ibuf);
		return false;
	}

	// Construct ut32 blocks from byte stream
	for (j = 0; j < len / 4; j++) {
		ibuf[j] = r_read_le32 (buf + 4 * j);
	}
	if (len & 0x3) {
		ut8 tail[4] = {0}; // Zero padding
		memcpy (tail, buf + (len & ~0x3), len & 0x3);
		ibuf[len / 4] = r_read_le32 (tail);
	}

	if (cry->dir == 0) {
		for (i = 0; i < blocks; i++) {
			// delta in number of ut32
			const int delta = (BLOCK_SIZE * i) / 4;
			serpent_encrypt (&st, ibuf + delta, tmp + delta);
		}
	} else if (cry->dir > 0) {
		for (i = 0; i < blocks; i++) {
			// delta in number of ut32
			const int delta = (BLOCK_SIZE * i) / 4;
			serpent_decrypt (&st, ibuf + delta, tmp + delta);
		}
	}

	// Construct ut32 blocks from byte stream
	int k;
	for (j = 0; j < size / 4; j++) {
		k = 4 * j;
		obuf[k] = tmp[j] & 0xff;
		obuf[k + 1] = (tmp[j] >> 8) & 0xff;
		obuf[k + 2] = (tmp[j] >> 16) & 0xff;
		obuf[k + 3] = (tmp[j] >> 24) & 0xff;
	}

	r_crypto_append (cry, obuf, size);
	free (obuf);
	free (ibuf);
	free (tmp);
	return true;
}

static bool final(RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_serpent = {
	.name = "serpent-ecb",
	.set_key = serpent_set_key,
	.get_key_size = serpent_get_key_size,
	.use = serpent_use,
	.update = update,
	.final = final
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_serpent,
	.version = R2_VERSION
};
#endif

