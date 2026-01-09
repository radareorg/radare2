/* radare - LGPL - Copyright 2009-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>

// RC2 Implementation
// clang-format off
static const ut8 PITABLE[256] = {
	0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
	0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
	0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
	0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
	0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
	0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
	0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
	0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
	0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
	0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
	0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
	0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
	0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
	0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
	0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
	0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD,
};
// clang-format on

#define RC2_BITS 1024
#define RC2_KEY_SIZE 64
#define RC2_BLOCK_SIZE 8

struct rc2_state {
	ut16 ekey[RC2_KEY_SIZE];
	int key_size;
};

static bool rc2_expandKey(struct rc2_state *state, const ut8 *key, int key_len) {
	int i;

	if (key_len < 1 || key_len > 128) {
		return false;
	}
	memcpy (state->ekey, key, key_len);

	// first loop
	for (i = key_len; i < 128; i++) {
		((ut8 *)state->ekey)[i] = PITABLE[(((ut8 *)state->ekey)[i - key_len] + ((ut8 *)state->ekey)[i - 1]) & 255];
	}

	int ekey_len = (RC2_BITS + 7) >> 3;
	i = 128 - ekey_len;
	((ut8 *)state->ekey)[i] = PITABLE[((ut8 *)state->ekey)[i] &(255 >> (7 & -RC2_BITS))];

	// second loop
	while (i--) {
		((ut8 *)state->ekey)[i] = PITABLE[((ut8 *)state->ekey)[i + 1] ^ ((ut8 *)state->ekey)[i + ekey_len]];
	}

	// generate the ut16 key
	for (i = RC2_KEY_SIZE - 1; i >= 0; i--) {
		state->ekey[i] = ((ut8 *)state->ekey)[i * 2] + (((ut8 *)state->ekey)[i * 2 + 1] << 8);
	}

	return true;
}

static void rc2_crypt8(struct rc2_state *state, const ut8 *inbuf, ut8 *outbuf) {
	int i;
	ut16 x76, x54, x32, x10;

	x76 = (inbuf[7] << 8) | inbuf[6];
	x54 = (inbuf[5] << 8) | inbuf[4];
	x32 = (inbuf[3] << 8) | inbuf[2];
	x10 = (inbuf[1] << 8) | inbuf[0];

	for (i = 0; i < 16; i++) {
		x10 += ((x32 & ~x76) + (x54 & x76)) + state->ekey[4 * i + 0];
		x10 = (x10 << 1) + (x10 >> 15 & 1);

		x32 += ((x54 & ~x10) + (x76 & x10)) + state->ekey[4 * i + 1];
		x32 = (x32 << 2) + (x32 >> 14 & 3);

		x54 += ((x76 & ~x32) + (x10 & x32)) + state->ekey[4 * i + 2];
		x54 = (x54 << 3) + (x54 >> 13 & 7);

		x76 += ((x10 & ~x54) + (x32 & x54)) + state->ekey[4 * i + 3];
		x76 = (x76 << 5) + (x76 >> 11 & 31);

		if (i == 4 || i == 10) {
			x10 += state->ekey[x76 & 63];
			x32 += state->ekey[x10 & 63];
			x54 += state->ekey[x32 & 63];
			x76 += state->ekey[x54 & 63];
		}
	}

	outbuf[0] = (ut8)x10;
	outbuf[1] = (ut8) (x10 >> 8);
	outbuf[2] = (ut8)x32;
	outbuf[3] = (ut8) (x32 >> 8);
	outbuf[4] = (ut8)x54;
	outbuf[5] = (ut8) (x54 >> 8);
	outbuf[6] = (ut8)x76;
	outbuf[7] = (ut8) (x76 >> 8);
}

static void rc2_dcrypt8(struct rc2_state *state, const ut8 *inbuf, ut8 *outbuf) {
	int i;
	ut16 x76, x54, x32, x10;

	x76 = (inbuf[7] << 8) | inbuf[6];
	x54 = (inbuf[5] << 8) | inbuf[4];
	x32 = (inbuf[3] << 8) | inbuf[2];
	x10 = (inbuf[1] << 8) | inbuf[0];

	for (i = 15; i >= 0; i--) {
		x76 &= 65535;
		x76 = (x76 << 11) | (x76 >> 5);
		x76 -= ((x10 & ~x54) | (x32 & x54)) + state->ekey[4 * i + 3];

		x76 &= 65535;
		x54 = (x54 << 13) | (x54 >> 3);
		x54 -= ((x76 & ~x32) | (x10 & x32)) + state->ekey[4 * i + 2];

		x32 &= 65535;
		x32 = (x32 << 14) | (x32 >> 2);
		x32 -= ((x54 & ~x10) | (x76 & x10)) + state->ekey[4 * i + 1];

		x10 &= 65535;
		x10 = (x10 << 15) | (x10 >> 1);
		x10 -= ((x32 & ~x76) | (x54 & x76)) + state->ekey[4 * i + 0];

		if (i == 5 || i == 11) {
			x76 -= state->ekey[x54 & 63];
			x54 -= state->ekey[x32 & 63];
			x32 -= state->ekey[x10 & 63];
			x10 -= state->ekey[x76 & 63];
		}
	}

	outbuf[0] = (ut8)x10;
	outbuf[1] = (ut8) (x10 >> 8);
	outbuf[2] = (ut8)x32;
	outbuf[3] = (ut8) (x32 >> 8);
	outbuf[4] = (ut8)x54;
	outbuf[5] = (ut8) (x54 >> 8);
	outbuf[6] = (ut8)x76;
	outbuf[7] = (ut8) (x76 >> 8);
}

static void rc2_dcrypt(struct rc2_state *state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	char data_block[RC2_BLOCK_SIZE + 1] = { 0 };
	char dcrypted_block[RC2_BLOCK_SIZE + 1] = { 0 };
	char *ptr = (char *)outbuf;
	int i, idx = 0;

	for (i = 0; i < buflen; i++) {
		data_block[idx] = inbuf[i];
		idx += 1;
		if (idx % RC2_BLOCK_SIZE == 0) {
			rc2_dcrypt8 (state, (const ut8 *)data_block, (ut8 *)dcrypted_block);
			memcpy (ptr, dcrypted_block, RC2_BLOCK_SIZE);
			ptr += RC2_BLOCK_SIZE;
			idx = 0;
		}
	}
}

static void rc2_crypt(struct rc2_state *state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	char crypted_block[RC2_BLOCK_SIZE] = { 0 };
	char data_block[RC2_BLOCK_SIZE] = { 0 };
	char *ptr = (char *)outbuf;
	int i, idx = 0;

	// divide it into blocks of RC2_BLOCK_SIZE
	for (i = 0; i < buflen; i++) {
		data_block[idx] = inbuf[i];
		idx += 1;
		if (idx % RC2_BLOCK_SIZE == 0) {
			rc2_crypt8 (state, (const ut8 *)data_block, (ut8 *)crypted_block);
			strncpy (ptr, crypted_block, RC2_BLOCK_SIZE);
			ptr += RC2_BLOCK_SIZE;
			idx = 0;
		}
	}
	size_t mod = idx % RC2_BLOCK_SIZE;
	if (mod) {
		while (idx % RC2_BLOCK_SIZE) {
			mod = idx % RC2_BLOCK_SIZE;
			data_block[mod] = 0;
			idx++;
		}
		rc2_crypt8 (state, (const ut8 *)data_block, (ut8 *)crypted_block);
		r_str_ncpy (ptr, crypted_block, RC2_BLOCK_SIZE);
	}
}

// RC4 Implementation
struct rc4_state {
	ut8 perm[256];
	ut8 index1;
	ut8 index2;
	int key_size;
};

static __inline void swap_bytes(ut8 *a, ut8 *b) {
	if (a != b) {
		ut8 temp = *a;
		*a = *b;
		*b = temp;
	}
}

static bool rc4_init(struct rc4_state *const state, const ut8 *key, int keylen) {
	ut8 j;
	int i;

	if (!state || !key || keylen < 1) {
		return false;
	}
	state->key_size = keylen;
	/* Initialize state with identity permutation */
	for (i = 0; i < 256; i++) {
		state->perm[i] = (ut8)i;
	}
	state->index1 = 0;
	state->index2 = 0;

	/* Randomize the permutation using key data */
	for (j = i = 0; i < 256; i++) {
		j += state->perm[i] + key[i % keylen];
		swap_bytes (&state->perm[i], &state->perm[j]);
	}
	return true;
}

static void rc4_crypt(struct rc4_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	if (!state || !inbuf || !outbuf || buflen < 1) {
		return;
	}
	int i;
	ut8 j;

	for (i = 0; i < buflen; i++) {
		/* Update modification indices */
		state->index1++;
		state->index2 += state->perm[state->index1];
		/* Modify permutation */
		swap_bytes (&state->perm[state->index1], &state->perm[state->index2]);
		/* Encrypt/decrypt next byte */
		j = state->perm[state->index1] + state->perm[state->index2];
		outbuf[i] = inbuf[i] ^ state->perm[j];
	}
}

// RC6 Implementation
#define RC6_Pw 0xb7e15163
#define RC6_Qw 0x9e3779b9
#define RC6_BLOCK_SIZE 16
#define RC6_r 20
#define RC6_w 32
#define RC6_ROTL(x, y) (((x) << ((y) &(RC6_w - 1))) | ((x) >> (RC6_w - ((y) &(RC6_w - 1)))))
#define RC6_ROTR(x, y) (((x) >> ((y) &(RC6_w - 1))) | ((x) << (RC6_w - ((y) &(RC6_w - 1)))))

struct rc6_state {
	ut32 S[2 * RC6_r + 4];
	int key_size;
};

static bool rc6_init(struct rc6_state *const state, const ut8 *key, int keylen, int direction) {
	if (keylen != 128 / 8 && keylen != 192 / 8 && keylen != 256 / 8) {
		return false;
	}

	int u = RC6_w / 8;
	int c = keylen / u;
	int t = 2 * RC6_r + 4;
#ifdef _MSC_VER
	ut32 *L = (ut32 *)malloc (sizeof (ut32) * c);
#else
	ut32 L[c];
#endif
	ut32 A = 0, B = 0, k = 0, j = 0;
	ut32 v = 3 * t; // originally v = 2 *((c > t)? c: t);

	int i, off;

	for (i = 0, off = 0; i < c; i++) {
		L[i] = ((key[off++] & 0xff));
		L[i] |= ((key[off++] & 0xff) << 8);
		L[i] |= ((key[off++] & 0xff) << 16);
		L[i] |= ((key[off++] & 0xff) << 24);
	}

	(state->S)[0] = RC6_Pw;
	for (i = 1; i < t; i++) {
		(state->S)[i] = (state->S)[i - 1] + RC6_Qw;
	}

	for (i = 0; i < v; i++) {
		A = (state->S)[k] = RC6_ROTL (((state->S)[k] + A + B), 3);
		B = L[j] = RC6_ROTL ((L[j] + A + B), (A + B));
		k = (k + 1) % t;
		j = (j + 1) % c;
	}

	state->key_size = keylen / 8;
#ifdef _MSC_VER
	free (L);
#endif
	return true;
}

static void rc6_encrypt(struct rc6_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut32 t, u;
	ut32 aux;
	ut32 data[RC6_BLOCK_SIZE / 4];
	int i;
	int off = 0;
	for (i = 0; i < RC6_BLOCK_SIZE / 4; i++) {
		data[i] = ((inbuf[off++] & 0xff));
		data[i] |= ((inbuf[off++] & 0xff) << 8);
		data[i] |= ((inbuf[off++] & 0xff) << 16);
		data[i] |= ((inbuf[off++] & 0xff) << 24);
	}

	ut32 A = data[0], B = data[1], C = data[2], D = data[3];

	// S is key
	B = B + (state->S)[0];
	D = D + (state->S)[1];

	for (i = 1; i <= RC6_r; i++) {
		t = RC6_ROTL (B *(2 * B + 1), 5); // lgw == 5
		u = RC6_ROTL (D *(2 * D + 1), 5);
		A = RC6_ROTL (A ^ t, u) + (state->S)[2 * i];
		C = RC6_ROTL (C ^ u, t) + (state->S)[2 * i + 1];

		aux = A;
		A = B;
		B = C;
		C = D;
		D = aux;
	}

	A = A + (state->S)[2 *(RC6_r + 1)];
	C = C + (state->S)[2 *(RC6_r + 1) + 1];
	data[0] = A;
	data[1] = B;
	data[2] = C;
	data[3] = D;

	for (i = 0; i < RC6_BLOCK_SIZE; i++) {
		outbuf[i] = (ut8) ((data[i / 4] >> (i % 4) * 8) & 0xff);
	}
}

static void rc6_decrypt(struct rc6_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut32 t, u;
	ut32 aux;
	ut32 data[RC6_BLOCK_SIZE / 4];
	int i;
	int off = 0;

	for (i = 0; i < RC6_BLOCK_SIZE / 4; i++) {
		data[i] = ((inbuf[off++] & 0xff));
		data[i] |= ((inbuf[off++] & 0xff) << 8);
		data[i] |= ((inbuf[off++] & 0xff) << 16);
		data[i] |= ((inbuf[off++] & 0xff) << 24);
	}

	ut32 A = data[0], B = data[1], C = data[2], D = data[3];

	C = C - (state->S)[2 *(RC6_r + 1) + 1];
	A = A - (state->S)[2 *(RC6_r + 1)];

	for (i = RC6_r; i >= 1; i--) {
		aux = D;
		D = C;
		C = B;
		B = A;
		A = aux;

		u = RC6_ROTL (D *(2 * D + 1), 5);
		t = RC6_ROTL (B *(2 * B + 1), 5);
		C = RC6_ROTR (C - (state->S)[2 * i + 1], t) ^ u;
		A = RC6_ROTR (A - (state->S)[2 * i], u) ^ t;
	}

	D = D - (state->S)[1];
	B = B - (state->S)[0];

	data[0] = A;
	data[1] = B;
	data[2] = C;
	data[3] = D;

	for (i = 0; i < RC6_BLOCK_SIZE; i++) {
		outbuf[i] = (ut8) ((data[i / 4] >> (i % 4) * 8) & 0xff);
	}
}

// Combined Plugin
static bool rc_check(const char *algo) {
	return algo && (!strcmp (algo, "rc2") || !strcmp (algo, "rc4") || !strcmp (algo, "rc6"));
}

static bool rc_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	free (cj->data);

	if (!strcmp (cj->subtype, "rc2")) {
		cj->data = R_NEW0 (struct rc2_state);
		struct rc2_state *state = cj->data;
		cj->flag = direction;
		state->key_size = RC2_BITS;
		return rc2_expandKey ((struct rc2_state *)cj->data, key, keylen);
	} else if (!strcmp (cj->subtype, "rc4")) {
		cj->data = R_NEW0 (struct rc4_state);
		return rc4_init ((struct rc4_state *)cj->data, key, keylen);
	} else if (!strcmp (cj->subtype, "rc6")) {
		cj->data = R_NEW0 (struct rc6_state);
		cj->flag = (direction == R_CRYPTO_DIR_DECRYPT);
		return rc6_init ((struct rc6_state *)cj->data, key, keylen, direction);
	}

	return false;
}

static int rc_get_key_size(RMutaSession *cj) {
	if (!cj->data) {
		return 0;
	}

	if (!strcmp (cj->subtype, "rc2")) {
		struct rc2_state *state = cj->data;
		return state->key_size;
	} else if (!strcmp (cj->subtype, "rc4")) {
		struct rc4_state *st = cj->data;
		return st->key_size;
	} else if (!strcmp (cj->subtype, "rc6")) {
		struct rc6_state *st = cj->data;
		return st->key_size;
	}

	return 0;
}

static bool rc_update(RMutaSession *cj, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}

	if (!strcmp (cj->subtype, "rc2")) {
		struct rc2_state *state = cj->data;
		if (!state) {
			free (obuf);
			return false;
		}
		switch (cj->flag) {
		case R_CRYPTO_DIR_ENCRYPT:
			rc2_crypt (state, buf, obuf, len);
			break;
		case R_CRYPTO_DIR_DECRYPT:
			rc2_dcrypt (state, buf, obuf, len);
			break;
		default:
			break;
		}
	} else if (!strcmp (cj->subtype, "rc4")) {
		struct rc4_state *st = cj->data;
		rc4_crypt (st, buf, obuf, len);
	} else if (!strcmp (cj->subtype, "rc6")) {
		if (len % RC6_BLOCK_SIZE != 0) {
			R_LOG_ERROR ("Input should be multiple of 128bit");
			free (obuf);
			return false;
		}
		struct rc6_state *st = cj->data;
		if (!st) {
			R_LOG_ERROR ("No key set for rc6");
			free (obuf);
			return false;
		}
		const int blocks = len / RC6_BLOCK_SIZE;
		int i;
		if (cj->flag) {
			for (i = 0; i < blocks; i++) {
				rc6_decrypt (st, buf + RC6_BLOCK_SIZE * i, obuf + RC6_BLOCK_SIZE * i);
			}
		} else {
			for (i = 0; i < blocks; i++) {
				rc6_encrypt (st, buf + RC6_BLOCK_SIZE * i, obuf + RC6_BLOCK_SIZE * i);
			}
		}
	}

	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return true;
}

static bool rc_end(RMutaSession *cj, const ut8 *buf, int len) {
	return rc_update (cj, buf, len);
}

static bool rc_fini(RMutaSession *cj) {
	R_FREE (cj->data);
	return true;
}

RMutaPlugin r_muta_plugin_rc = {
	.meta = {
		.name = "rc",
		.desc = "Rivest Cipher (RC2, RC4, RC6)",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.type = R_MUTA_TYPE_CRYPTO,
	.implements = "rc2,rc4,rc6",
	.check = rc_check,
	.set_key = rc_set_key,
	.get_key_size = rc_get_key_size,
	.update = rc_update,
	.end = rc_end,
	.fini = rc_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_rc,
	.version = R2_VERSION
};
#endif