// original code from:
//====================
// advanced encryption standard
// author: karl malbrain, malbrain@yahoo.com
//
// adapted from Christophe Devine's tables
// and George Anescu's c++ code.

#include "crypto_aes_algo.h"

#define Nb 4 // number of columns in the state & expanded key

// #define Nk 4  // number of columns in a key
// #define Nr 10 // number of rounds in encryption
// #define AES_KEY (4 * Nk)
// #define ROUND_KEY_COUNT ((Nr + 1) * 4)

static const ut8 Rcon[30] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	0x1b, 0x36, 0x6c, 0xc0, 0xab, 0x4d, 0x9a, 0x2f,
	0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
	0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};

typedef struct {
	// #define Nr_AES256 (16) /* st->rounds */
	// #define Nr_AES256 (6 + ((256 / 8) / 4))
	// ut32 key[2][Nr_AES256 + 1][Nb];
	ut32 key[2][17][4];
} RCryptoAESExponent;

// Expand a user-supplied key material into a session key.
// key        - The 128/192/256-bit user-key to use.
void aes_expkey(const RCryptoAESState *st, RCryptoAESExponent *exp) {
	if (!st) {
		return;
	}
	// ut32 expkey[2][st->rounds + 1][Nb];
	// memcpy (&expkey, _expkey, 2 * (st->rounds + 1) * Nb);
	const int ROUND_KEY_COUNT = 4 * (1 + st->rounds);
	ut32 tt;
	st32 idx = 0, t = 0;
	const ut8 *key = st->key;
	st32 i, j, r;

	ut32 *tk = (ut32*)malloc (sizeof (ut32) * st->columns);
	if (!tk) {
		return;
	}

	for (i = 0; i <= st->rounds; i++) {
		for (j = 0; j < Nb; j++) {
			exp->key[0][i][j] = 0;
		}
	}

	for (i = 0; i <= st->rounds; i++) {
		for (j = 0; j < Nb; j++) {
			exp->key[1][i][j] = 0;
		}
	}

	// Copy user material bytes into temporary ints
	for (i = 0; i < st->columns; i++) {
		tk[i] = *key++ << 24;
		tk[i] |= *key++ << 16;
		tk[i] |= *key++ << 8;
		tk[i] |= *key++;
	}

	// Copy values into round key arrays
	for (j = 0; j < st->columns && t < ROUND_KEY_COUNT; j++, t++) {
		exp->key[0][t / Nb][t % Nb] = tk[j];
		exp->key[1][st->rounds - (t / Nb)][t % Nb] = tk[j];
	}

	while (t < ROUND_KEY_COUNT) {
		// Extrapolate using phi (the round key evolution function)
		tt = tk[st->columns - 1];
		tk[0] ^= Sbox[(ut8)(tt >> 16)] << 24 ^ Sbox[(ut8)(tt >> 8)] << 16 ^
			Sbox[(ut8)tt] << 8 ^ Sbox[(ut8)(tt >> 24)] ^ Rcon[idx++] << 24;

		if (st->columns != 8) {
			for (i = 1, j = 0; i < st->columns;) {
				tk[i++] ^= tk[j++];
			}
		} else {
			for (i = 1, j = 0; i < st->columns / 2;) {
				tk[i++] ^= tk[j++];
			}
			tt = tk[st->columns / 2 - 1];
			tk[st->columns / 2] ^= Sbox[(ut8)tt] ^ Sbox[(ut8)(tt >> 8)] << 8 ^
				Sbox[(ut8)(tt >> 16)] << 16 ^
				Sbox[(ut8)(tt >> 24)] << 24;
			for (j = st->columns / 2, i = j + 1; i < st->columns;) {
				tk[i++] ^= tk[j++];
			}
		}

		// Copy values into round key arrays
		for (j = 0; j < st->columns && t < ROUND_KEY_COUNT; j++, t++) {
			exp->key[0][t / Nb][t % Nb] = tk[j];
			exp->key[1][st->rounds - (t / Nb)][t % Nb] = tk[j];
		}
	}
	// Inverse MixColumn where needed
	for (r = 1; r < st->rounds; r++) {
		for (j = 0; j < Nb; j++) {
			tt = exp->key[1][r][j];
			exp->key[1][r][j] = U0[(ut8)(tt >> 24)] ^ U1[(ut8)(tt >> 16)] ^
				U2[(ut8)(tt >> 8)] ^ U3[(ut8)tt];
		}
	}
	free (tk);
}

// Convenience method to encrypt exactly one block of plaintext, assuming
// Rijndael's default block size (128-bit).
// in         - The plaintext
// result     - The ciphertext generated from a plaintext using the key
void aes_encrypt(RCryptoAESState *st, ut8 *in, ut8 *result) {
	RCryptoAESExponent exp;
	memset (&exp, 0, sizeof (exp));
	aes_expkey (st, &exp);

	ut32 t0, t1, t2, t3, tt;
	ut32 a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= exp.key[0][0][0];

	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= exp.key[0][0][1];

	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= exp.key[0][0][2];

	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= exp.key[0][0][3];

	// Apply Round Transforms
	for (r = 1; r < st->rounds; r++) {
		a0 = (FT0[(ut8)(t0 >> 24)] ^ FT1[(ut8)(t1 >> 16)] ^ FT2[(ut8)(t2 >> 8)] ^
				FT3[(ut8)t3]);
		a1 = (FT0[(ut8)(t1 >> 24)] ^ FT1[(ut8)(t2 >> 16)] ^ FT2[(ut8)(t3 >> 8)] ^
				FT3[(ut8)t0]);
		a2 = (FT0[(ut8)(t2 >> 24)] ^ FT1[(ut8)(t3 >> 16)] ^ FT2[(ut8)(t0 >> 8)] ^
				FT3[(ut8)t1]);
		a3 = (FT0[(ut8)(t3 >> 24)] ^ FT1[(ut8)(t0 >> 16)] ^ FT2[(ut8)(t1 >> 8)] ^
				FT3[(ut8)t2]);
		t0 = a0 ^ exp.key[0][r][0];
		t1 = a1 ^ exp.key[0][r][1];
		t2 = a2 ^ exp.key[0][r][2];
		t3 = a3 ^ exp.key[0][r][3];
	}

	// Last Round is special

	tt = exp.key[0][st->rounds][0];
	result[0] = Sbox[(ut8)(t0 >> 24)] ^ (ut8)(tt >> 24);
	result[1] = Sbox[(ut8)(t1 >> 16)] ^ (ut8)(tt >> 16);
	result[2] = Sbox[(ut8)(t2 >> 8)] ^ (ut8)(tt >> 8);
	result[3] = Sbox[(ut8)t3] ^ (ut8)tt;

	tt = exp.key[0][st->rounds][1];
	result[4] = Sbox[(ut8)(t1 >> 24)] ^ (ut8)(tt >> 24);
	result[5] = Sbox[(ut8)(t2 >> 16)] ^ (ut8)(tt >> 16);
	result[6] = Sbox[(ut8)(t3 >> 8)] ^ (ut8)(tt >> 8);
	result[7] = Sbox[(ut8)t0] ^ (ut8)tt;

	tt = exp.key[0][st->rounds][2];
	result[8] = Sbox[(ut8)(t2 >> 24)] ^ (ut8)(tt >> 24);
	result[9] = Sbox[(ut8)(t3 >> 16)] ^ (ut8)(tt >> 16);
	result[10] = Sbox[(ut8)(t0 >> 8)] ^ (ut8)(tt >> 8);
	result[11] = Sbox[(ut8)t1] ^ (ut8)tt;

	tt = exp.key[0][st->rounds][3];
	result[12] = Sbox[(ut8)(t3 >> 24)] ^ (ut8)(tt >> 24);
	result[13] = Sbox[(ut8)(t0 >> 16)] ^ (ut8)(tt >> 16);
	result[14] = Sbox[(ut8)(t1 >> 8)] ^ (ut8)(tt >> 8);
	result[15] = Sbox[(ut8)t2] ^ (ut8)tt;
}

// Convenience method to decrypt exactly one block of plaintext, assuming
// Rijndael's default block size (128-bit).
// in         - The ciphertext.
// result     - The plaintext generated from a ciphertext using the session key.
void aes_decrypt(RCryptoAESState *st, ut8 *in, ut8 *result) {
	RCryptoAESExponent exp;
	memset (&exp, 0, sizeof (exp));

	aes_expkey (st, &exp);

	ut32 t0, t1, t2, t3, tt;
	ut32 a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= exp.key[1][0][0];

	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= exp.key[1][0][1];

	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= exp.key[1][0][2];

	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= exp.key[1][0][3];

	// Apply round transforms
	for (r = 1; r < st->rounds; r++) {
		a0 = (RT0[(ut8)(t0 >> 24)] ^ RT1[(ut8)(t3 >> 16)] ^ RT2[(ut8)(t2 >> 8)] ^ RT3[(ut8)t1]);
		a1 = (RT0[(ut8)(t1 >> 24)] ^ RT1[(ut8)(t0 >> 16)] ^ RT2[(ut8)(t3 >> 8)] ^ RT3[(ut8)t2]);
		a2 = (RT0[(ut8)(t2 >> 24)] ^ RT1[(ut8)(t1 >> 16)] ^ RT2[(ut8)(t0 >> 8)] ^ RT3[(ut8)t3]);
		a3 = (RT0[(ut8)(t3 >> 24)] ^ RT1[(ut8)(t2 >> 16)] ^ RT2[(ut8)(t1 >> 8)] ^ RT3[(ut8)t0]);
		t0 = a0 ^ exp.key[1][r][0];
		t1 = a1 ^ exp.key[1][r][1];
		t2 = a2 ^ exp.key[1][r][2];
		t3 = a3 ^ exp.key[1][r][3];
	}

	// Last Round is special
	tt = exp.key[1][st->rounds][0];
	result[0] = InvSbox[(ut8)(t0 >> 24)] ^ (ut8)(tt >> 24);
	result[1] = InvSbox[(ut8)(t3 >> 16)] ^ (ut8)(tt >> 16);
	result[2] = InvSbox[(ut8)(t2 >> 8)] ^ (ut8)(tt >> 8);
	result[3] = InvSbox[(ut8)t1] ^ (ut8)tt;

	tt = exp.key[1][st->rounds][1];
	result[4] = InvSbox[(ut8)(t1 >> 24)] ^ (ut8)(tt >> 24);
	result[5] = InvSbox[(ut8)(t0 >> 16)] ^ (ut8)(tt >> 16);
	result[6] = InvSbox[(ut8)(t3 >> 8)] ^ (ut8)(tt >> 8);
	result[7] = InvSbox[(ut8)t2] ^ (ut8)tt;

	tt = exp.key[1][st->rounds][2];
	result[8] = InvSbox[(ut8)(t2 >> 24)] ^ (ut8)(tt >> 24);
	result[9] = InvSbox[(ut8)(t1 >> 16)] ^ (ut8)(tt >> 16);
	result[10] = InvSbox[(ut8)(t0 >> 8)] ^ (ut8)(tt >> 8);
	result[11] = InvSbox[(ut8)t3] ^ (ut8)tt;

	tt = exp.key[1][st->rounds][3];
	result[12] = InvSbox[(ut8)(t3 >> 24)] ^ (ut8)(tt >> 24);
	result[13] = InvSbox[(ut8)(t2 >> 16)] ^ (ut8)(tt >> 16);
	result[14] = InvSbox[(ut8)(t1 >> 8)] ^ (ut8)(tt >> 8);
	result[15] = InvSbox[(ut8)t0] ^ (ut8)tt;
}

R_IPI bool aes_ecb(RCryptoAESState *st, ut8 *const ibuf, ut8 *obuf, bool encrypt, const int blocks) {
	int i;

	if (encrypt) {
		for (i = 0; i < blocks; i++) {
			const int delta = AES_BLOCK_SIZE * i;
			aes_encrypt (st, ibuf + delta, obuf + delta);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			const int delta = AES_BLOCK_SIZE * i;
			aes_decrypt (st, ibuf + delta, obuf + delta);
		}
	}
	return true;
}

R_IPI bool aes_wrap(RCryptoAESState *st, const ut8 *ibuf, ut8 *obuf, const ut8 *iv, bool encrypt, int blocks) {
	ut8 tmp[16] = { 0 };
	long *tmp_ptr = (long *)tmp;
	ut64 t = 0;
	int i, j;
	long *obuf_ptr = (long *)obuf;

	if (encrypt) {
		// Encrypt
		memcpy (obuf, iv, AES_WRAP_BLOCK_SIZE);
		memcpy (obuf + AES_WRAP_BLOCK_SIZE, ibuf, blocks * AES_WRAP_BLOCK_SIZE);
		for (j = 0; j <= 5; j++) {
			for (i = 0; i < blocks; i++) {
				/* B = AES(K, A | R[i]) */
				*tmp_ptr = *obuf_ptr;
				*(tmp_ptr + 1) = *(obuf_ptr + i + 1);
				aes_encrypt (st, tmp, tmp);

				/* A = MSB(64, B) ^ t */
				t++;
				t = r_swap_ut64 (t);
				*obuf_ptr = t ^ *tmp_ptr;
				t = r_swap_ut64 (t);

				/* R[i] = LSB(64, B) */
				*(obuf_ptr + i + 1) = *(tmp_ptr + 1);
			}
		}
	} else {
		// Decrypt
		memcpy (obuf, ibuf, blocks * AES_WRAP_BLOCK_SIZE);
		blocks -= 1;
		t = 6 * blocks;
		for (j = 0; j <= 5; j++) {
			for (i = blocks; i >= 1; i--) {
				/* B = AES^-1( (A ^ t)| R[i] ) */
				t = r_swap_ut64 (t);
				*tmp_ptr = t ^ *obuf_ptr;
				t = r_swap_ut64 (t);
				t--;
				*(tmp_ptr + 1) = *(obuf_ptr + i);
				aes_decrypt (st, tmp, tmp);

				/* A = MSB_64(B) */
				*obuf_ptr = *tmp_ptr;
				/* R[i] = LSB_64(B) */
				*(obuf_ptr + i) = *(tmp_ptr + 1);
			}
		}
		if (memcmp (iv, obuf, AES_WRAP_BLOCK_SIZE)) {
			R_LOG_ERROR ("Invalid integrity check");
			return false;
		}
		// The source buffer "obuf + 8" potentially overlaps with the destination buffer "obuf", which results in undefined behavior for "memcpy".
		memcpy (obuf, obuf + AES_WRAP_BLOCK_SIZE, blocks * AES_WRAP_BLOCK_SIZE);
	}
	return true;
}

R_IPI bool aes_cbc(RCryptoAESState *st, ut8 *ibuf, ut8 *obuf, ut8 *iv, bool encrypt, const int blocks) {
	int i, j;
	if (encrypt) {
		for (i = 0; i < blocks; i++) {
			for (j = 0; j < AES_BLOCK_SIZE; j++) {
				ibuf[i * AES_BLOCK_SIZE + j] ^= iv[j];
			}
			aes_encrypt (st, ibuf + AES_BLOCK_SIZE * i, obuf + AES_BLOCK_SIZE * i);
			memcpy (iv, obuf + AES_BLOCK_SIZE * i, AES_BLOCK_SIZE);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			aes_decrypt (st, ibuf + AES_BLOCK_SIZE * i, obuf + AES_BLOCK_SIZE * i);
			for (j = 0; j < AES_BLOCK_SIZE; j++) {
				obuf[i * AES_BLOCK_SIZE + j] ^= iv[j];
			}
			memcpy (iv, ibuf + AES_BLOCK_SIZE * i, AES_BLOCK_SIZE);
		}
	}
	return true;
}
