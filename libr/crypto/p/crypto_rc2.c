#include <r_lib.h>
#include <r_crypto.h>

#define BITS 1024
#define RC2_KEY_SIZE 64 // bytes
#define BLOCK_SIZE 8    // bytes

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

struct rc2_state {
	ut16 ekey[RC2_KEY_SIZE];
	int key_size;
};

// takes a 8-128 len ut8 key
// expands it to a 64 len ut16 key
static bool rc2_expandKey(struct rc2_state *state, const ut8 *key, int key_len) {
	int i;

	if (key_len < 1 || key_len > 128) {
		return false;
	}
	memcpy(state->ekey, key, key_len);

	// first loop
 	for (i = key_len; i < 128; i++) {
 		((ut8 *)state->ekey)[i] = PITABLE[(((ut8 *)state->ekey)[i - key_len] + ((ut8 *)state->ekey)[i - 1]) & 255];
 	}

	int ekey_len = (BITS + 7) >> 3;
	i = 128 - ekey_len;
 	((ut8 *)state->ekey)[i] = PITABLE[((ut8 *)state->ekey)[i] & (255 >> (7 & -BITS))];

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

	outbuf[0] = (ut8) x10;
	outbuf[1] = (ut8) (x10 >> 8);
	outbuf[2] = (ut8) x32;
	outbuf[3] = (ut8) (x32 >> 8);
	outbuf[4] = (ut8) x54;
	outbuf[5] = (ut8) (x54 >> 8);
	outbuf[6] = (ut8) x76;
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

	outbuf[0] = (ut8) x10;
	outbuf[1] = (ut8) (x10 >> 8);
	outbuf[2] = (ut8) x32;
	outbuf[3] = (ut8) (x32 >> 8);
	outbuf[4] = (ut8) x54;
	outbuf[5] = (ut8) (x54 >> 8);
	outbuf[6] = (ut8) x76;
	outbuf[7] = (ut8) (x76 >> 8);
}

static void rc2_dcrypt(struct rc2_state *state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	char data_block[BLOCK_SIZE + 1] = {0};
	int idx = 0;
	char dcrypted_block[BLOCK_SIZE + 1] = {0};
	char *ptr = (char *) outbuf;

	for (i = 0; i < buflen; i++) {
		data_block[idx] = inbuf[i];
		idx += 1;
		if (idx % BLOCK_SIZE == 0) {
			rc2_dcrypt8 (state, (const ut8 *) data_block, (ut8 *) dcrypted_block);
			memcpy (ptr, dcrypted_block, BLOCK_SIZE);
			ptr += BLOCK_SIZE;
			idx = 0;
		}
	}
}

static void rc2_crypt(struct rc2_state *state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	char data_block[BLOCK_SIZE] = {0};
	int idx = 0;

	char crypted_block[BLOCK_SIZE] = {0};
	char *ptr = (char *) outbuf;

	// divide it into blocks of BLOCK_SIZE
	for (i = 0; i < buflen; i++) {
		data_block[idx] = inbuf[i];
		idx += 1;
		if (idx % BLOCK_SIZE == 0) {
			rc2_crypt8(state, (const ut8 *) data_block, (ut8 *) crypted_block);
			strncpy(ptr, crypted_block, BLOCK_SIZE);
			ptr += BLOCK_SIZE;
			idx = 0;
		}
	}

	if (idx % 8) {
		while (idx % 8) {
			data_block[idx++] = 0;
		}
		rc2_crypt8(state, (const ut8 *) data_block, (ut8 *) crypted_block);
		strncpy(ptr, crypted_block, 8);
	}
}

///////////////////////////////////////////////////////////

static struct rc2_state state;
static int flag = 0;

static bool rc2_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	flag = direction;
	state.key_size = 1024;
	return rc2_expandKey(&state, key, keylen);
}

static int rc2_get_key_size(RCrypto *cry) {
	return state.key_size;
}

static bool rc2_use(const char *algo) {
	return !strcmp (algo, "rc2");
}

static bool update(RCrypto *cry, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	if (flag == 0) {
		rc2_crypt (&state, buf, obuf, len);
	} else if (flag == 1) {
		rc2_dcrypt (&state, buf, obuf, len);
	}
	r_crypto_append(cry, obuf, len);
	free (obuf);
	return true;
}

static bool final(RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_rc2 = {
	.name = "rc2",
	.set_key = rc2_set_key,
	.get_key_size = rc2_get_key_size,
	.use = rc2_use,
	.update = update,
	.final = final
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_rc2,
	.version = R2_VERSION
};
#endif

#if HAVE_MAIN
int main() {
	ut8 out[16];
	struct rc2_state st;
	st.key_size = 3;
	/* encrypt */
	rc2_expandKey ((const ut8*)"key", 3, BITS, &st);
	rc2_crypt(&st, (const ut8 *)"12345678abc", out, 11);
	eprintf ("%s\n", (const char *)out);
	rc2_dcrypt(&st, (const ut8 *)out, out, sizeof(out));
	eprintf ("%s\n", (const char *)out);
	return 0;
}
#endif
