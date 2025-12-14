/* radare - LGPL - Copyright 2017-2025 - deroad */

#include <r_muta.h>
#include "algo/des.inc.c"

struct des_state {
	ut32 keylo[16]; // round key low
	ut32 keyhi[16]; // round key hi
	ut32 buflo; // buf low
	ut32 bufhi; // buf hi
	int key_size;
	int rounds;
	int i;
};

static ut32 be32(const ut8 *buf4) {
	ut32 val = buf4[0] << 8;
	val |= buf4[1];
	val <<= 8;
	val |= buf4[2];
	val <<= 8;
	val |= buf4[3];
	return val;
}

static void wbe32(ut8 *buf4, ut32 val) {
	buf4[0] = (val >> 24);
	buf4[1] = (val >> 16) & 0xFF;
	buf4[2] = (val >> 8) & 0xFF;
	buf4[3] = val & 0xFF;
}

static int des_encrypt(struct des_state *st, const ut8 *input, ut8 *output) {
	if (!st || !input || !output) {
		return false;
	}
	st->buflo = be32 (input + 0);
	st->bufhi = be32 (input + 4);

	// first permutation
	r_des_permute_block0 (&st->buflo, &st->bufhi);

	for (st->i = 0; st->i < 16; st->i++) {
		r_des_round (&st->buflo, &st->bufhi, &st->keylo[st->i], &st->keyhi[st->i]);
	}
	// last permutation
	r_des_permute_block1 (&st->bufhi, &st->buflo);

	// result
	wbe32 (output + 0, st->bufhi);
	wbe32 (output + 4, st->buflo);

	return true;
}

static bool des_decrypt(struct des_state *st, const ut8 *input, ut8 *output) {
	R_RETURN_VAL_IF_FAIL (st && input && output, false);
	st->buflo = be32 (input + 0);
	st->bufhi = be32 (input + 4);
	// first permutation
	r_des_permute_block0 (&st->buflo, &st->bufhi);

	for (st->i = 0; st->i < 16; st->i++) {
		r_des_round (&st->buflo, &st->bufhi, &st->keylo[15 - st->i], &st->keyhi[15 - st->i]);
	}

	// last permutation
	r_des_permute_block1 (&st->bufhi, &st->buflo);
	// result
	wbe32 (output + 0, st->bufhi);
	wbe32 (output + 4, st->buflo);
	return true;
}

static bool des_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	ut32 keylo, keyhi, i;
	if (keylen != DES_KEY_SIZE) {
		return false;
	}
	// splitting the key in hi & lo
	keylo = be32 (key);
	keyhi = be32 (key + 4);

	free (cj->data);
	cj->data = R_NEW0 (struct des_state);
	struct des_state *st = cj->data;
	st->key_size = DES_KEY_SIZE;
	st->rounds = 16;
	cj->dir = direction; // = direction == 0;
	// key permutation to derive round keys
	r_des_permute_key (&keylo, &keyhi);

	for (i = 0; i < 16; i++) {
		// filling round keys space
		r_des_round_key (i, &st->keylo[i], &st->keyhi[i], &keylo, &keyhi);
	}

	return true;
}

static int des_get_key_size(RMutaSession *cj) {
	struct des_state *st = cj->data;
	return st? st->key_size: 0;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (len <= 0) {
		return false;
	}
	struct des_state *st = cj->data;
	if (!st) {
		R_LOG_ERROR ("No key set");
		return false;
	}

	// Pad to the block size, do not append dummy block
	const int diff = (DES_BLOCK_SIZE - (len % DES_BLOCK_SIZE)) % DES_BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / DES_BLOCK_SIZE;

	ut8 *const obuf = calloc (1, size);
	if (!obuf) {
		return false;
	}

	ut8 *const ibuf = calloc (1, size);
	if (!ibuf) {
		free (obuf);
		return false;
	}

	memset (ibuf + len, 0, (size - len));
	memcpy (ibuf, buf, len);
	// got it from AES, should be changed??
	// Padding should start like 100000...
	// if (diff) {
	//   ibuf[len] = 8; //0b1000;
	//  }

	int i;
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		for (i = 0; i < blocks; i++) {
			ut32 next = (DES_BLOCK_SIZE * i);
			des_encrypt (st, ibuf + next, obuf + next);
		}
		break;
	case R_CRYPTO_DIR_DECRYPT:
		for (i = 0; i < blocks; i++) {
			ut32 next = (DES_BLOCK_SIZE * i);
			des_decrypt (st, ibuf + next, obuf + next);
		}
		break;
	}

	r_muta_session_append (cj, obuf, size);
	free (obuf);
	free (ibuf);
	return 0;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_des = {
	.type = R_MUTA_TYPE_CRYPTO,
	.implements = "des-ecb",
	.meta = {
		.name = "des-ecb",
		.author = "deroad",
		.desc = "DES with with Electronic Code Book mode",
		.license = "LGPL-3.0-only",
	},
	.set_key = des_set_key,
	.get_key_size = des_get_key_size,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_des,
	.version = R2_VERSION
};
#endif
