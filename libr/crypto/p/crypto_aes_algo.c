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

// Expand a user-supplied key material into a session key.
// key        - The 128/192/256-bit user-key to use.
//expkey[2][Nr + 1][Nb]
//void aes_expkey (const struct aes_state *st, ut32 ***expkey) { //expkey[2][st->rounds + 1][Nb]) {
#if defined (__GNUC__)
void aes_expkey (const struct aes_state *st, ut32 expkey[2][st->rounds + 1][Nb])
#else
// XXX this is wrong, but at least it compiles
#ifdef _MSC_VER
#pragma message ("AES broken for non-gcc compilers")
#else
#warning AES broken for non-gcc compilers
#endif
#define Nr_AES256 (6 + ((256 / 8) / 4))
void aes_expkey (const struct aes_state *st, ut32 expkey[2][Nr_AES256 + 1][Nb])
#endif
{
	// ut32 expkey[2][st->rounds + 1][Nb];
	// memcpy (&expkey, _expkey, 2 * (st->rounds + 1) * Nb);
	int ROUND_KEY_COUNT = 4 * (1 + st->rounds);
#ifdef _MSC_VER
	ut32 *tk = (ut32*)malloc (sizeof (ut32) * st->columns);
#else
	ut32 tk[st->columns];
#endif
	ut32 tt;
	st32 idx = 0, t = 0;
	const ut8 *key = st->key;
	st32 i, j, r;

	for (i = 0; i <= st->rounds; i++) {
		for (j = 0; j < Nb; j++) {
			expkey[0][i][j] = 0;
		}
	}

	for (i = 0; i <= st->rounds; i++) {
		for (j = 0; j < Nb; j++) {
			expkey[1][i][j] = 0;
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
		expkey[0][t / Nb][t % Nb] = tk[j];
		expkey[1][st->rounds - (t / Nb)][t % Nb] = tk[j];
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
			expkey[0][t / Nb][t % Nb] = tk[j];
			expkey[1][st->rounds - (t / Nb)][t % Nb] = tk[j];
		}
	}
	// Inverse MixColumn where needed
	for (r = 1; r < st->rounds; r++) {
		for (j = 0; j < Nb; j++) {
			tt = expkey[1][r][j];
			expkey[1][r][j] = U0[(ut8)(tt >> 24)] ^ U1[(ut8)(tt >> 16)] ^
				U2[(ut8)(tt >> 8)] ^ U3[(ut8)tt];
		}
	}
#ifdef _MSC_VER
	free (tk);
#endif
}

// Convenience method to encrypt exactly one block of plaintext, assuming
// Rijndael's default block size (128-bit).
// in         - The plaintext
// result     - The ciphertext generated from a plaintext using the key
void aes_encrypt (struct aes_state *st, ut8 *in, ut8 *result) {
#if defined(_MSC_VER) || defined(__TINYC__)
	ut32 expkey[2][Nr_AES256 + 1][Nb];
#else
	ut32 expkey[2][st->rounds + 1][Nb];
#endif
	aes_expkey(st, expkey);

	ut32 t0, t1, t2, t3, tt;
	ut32 a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= expkey[0][0][0];

	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= expkey[0][0][1];

	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= expkey[0][0][2];

	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= expkey[0][0][3];

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
		t0 = a0 ^ expkey[0][r][0];
		t1 = a1 ^ expkey[0][r][1];
		t2 = a2 ^ expkey[0][r][2];
		t3 = a3 ^ expkey[0][r][3];
	}

	// Last Round is special

	tt = expkey[0][st->rounds][0];
	result[0] = Sbox[(ut8)(t0 >> 24)] ^ (ut8)(tt >> 24);
	result[1] = Sbox[(ut8)(t1 >> 16)] ^ (ut8)(tt >> 16);
	result[2] = Sbox[(ut8)(t2 >> 8)] ^ (ut8)(tt >> 8);
	result[3] = Sbox[(ut8)t3] ^ (ut8)tt;

	tt = expkey[0][st->rounds][1];
	result[4] = Sbox[(ut8)(t1 >> 24)] ^ (ut8)(tt >> 24);
	result[5] = Sbox[(ut8)(t2 >> 16)] ^ (ut8)(tt >> 16);
	result[6] = Sbox[(ut8)(t3 >> 8)] ^ (ut8)(tt >> 8);
	result[7] = Sbox[(ut8)t0] ^ (ut8)tt;

	tt = expkey[0][st->rounds][2];
	result[8] = Sbox[(ut8)(t2 >> 24)] ^ (ut8)(tt >> 24);
	result[9] = Sbox[(ut8)(t3 >> 16)] ^ (ut8)(tt >> 16);
	result[10] = Sbox[(ut8)(t0 >> 8)] ^ (ut8)(tt >> 8);
	result[11] = Sbox[(ut8)t1] ^ (ut8)tt;

	tt = expkey[0][st->rounds][3];
	result[12] = Sbox[(ut8)(t3 >> 24)] ^ (ut8)(tt >> 24);
	result[13] = Sbox[(ut8)(t0 >> 16)] ^ (ut8)(tt >> 16);
	result[14] = Sbox[(ut8)(t1 >> 8)] ^ (ut8)(tt >> 8);
	result[15] = Sbox[(ut8)t2] ^ (ut8)tt;
}

// Convenience method to decrypt exactly one block of plaintext, assuming
// Rijndael's default block size (128-bit).
// in         - The ciphertext.
// result     - The plaintext generated from a ciphertext using the session key.
void aes_decrypt (struct aes_state *st, ut8 *in, ut8 *result) {
#if defined(_MSC_VER) || defined(__TINYC__)
	ut32 expkey[2][Nr_AES256 + 1][Nb];
#else
	ut32 expkey[2][st->rounds + 1][Nb];
#endif

	aes_expkey(st, expkey);

	ut32 t0, t1, t2, t3, tt;
	ut32 a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= expkey[1][0][0];

	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= expkey[1][0][1];

	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= expkey[1][0][2];

	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= expkey[1][0][3];

	// Apply round transforms
	for (r = 1; r < st->rounds; r++) {
		a0 = (RT0[(ut8)(t0 >> 24)] ^ RT1[(ut8)(t3 >> 16)] ^ RT2[(ut8)(t2 >> 8)] ^ RT3[(ut8)t1]);
		a1 = (RT0[(ut8)(t1 >> 24)] ^ RT1[(ut8)(t0 >> 16)] ^ RT2[(ut8)(t3 >> 8)] ^ RT3[(ut8)t2]);
		a2 = (RT0[(ut8)(t2 >> 24)] ^ RT1[(ut8)(t1 >> 16)] ^ RT2[(ut8)(t0 >> 8)] ^ RT3[(ut8)t3]);
		a3 = (RT0[(ut8)(t3 >> 24)] ^ RT1[(ut8)(t2 >> 16)] ^ RT2[(ut8)(t1 >> 8)] ^ RT3[(ut8)t0]);
		t0 = a0 ^ expkey[1][r][0];
		t1 = a1 ^ expkey[1][r][1];
		t2 = a2 ^ expkey[1][r][2];
		t3 = a3 ^ expkey[1][r][3];
	}

	// Last Round is special
	tt = expkey[1][st->rounds][0];
	result[0] = InvSbox[(ut8)(t0 >> 24)] ^ (ut8)(tt >> 24);
	result[1] = InvSbox[(ut8)(t3 >> 16)] ^ (ut8)(tt >> 16);
	result[2] = InvSbox[(ut8)(t2 >> 8)] ^ (ut8)(tt >> 8);
	result[3] = InvSbox[(ut8)t1] ^ (ut8)tt;

	tt = expkey[1][st->rounds][1];
	result[4] = InvSbox[(ut8)(t1 >> 24)] ^ (ut8)(tt >> 24);
	result[5] = InvSbox[(ut8)(t0 >> 16)] ^ (ut8)(tt >> 16);
	result[6] = InvSbox[(ut8)(t3 >> 8)] ^ (ut8)(tt >> 8);
	result[7] = InvSbox[(ut8)t2] ^ (ut8)tt;

	tt = expkey[1][st->rounds][2];
	result[8] = InvSbox[(ut8)(t2 >> 24)] ^ (ut8)(tt >> 24);
	result[9] = InvSbox[(ut8)(t1 >> 16)] ^ (ut8)(tt >> 16);
	result[10] = InvSbox[(ut8)(t0 >> 8)] ^ (ut8)(tt >> 8);
	result[11] = InvSbox[(ut8)t3] ^ (ut8)tt;

	tt = expkey[1][st->rounds][3];
	result[12] = InvSbox[(ut8)(t3 >> 24)] ^ (ut8)(tt >> 24);
	result[13] = InvSbox[(ut8)(t2 >> 16)] ^ (ut8)(tt >> 16);
	result[14] = InvSbox[(ut8)(t1 >> 8)] ^ (ut8)(tt >> 8);
	result[15] = InvSbox[(ut8)t0] ^ (ut8)tt;
}
