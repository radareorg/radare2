/* radare - LGPL - Copyright 2017-2022 - Sylvain Pelissier
 * Implementation of SM4 block cipher
 * https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
 *
 * */

#include <r_crypto.h>
#include <r_crypto/r_sm4.h>
#include <r_util.h>
#include <memory.h>

#define BLOCK_SIZE   16
#define SM4_KEY_SIZE 16

/* Rotate left */
#define ROTL(rs, sh) (((rs) << (sh)) | ((rs) >> (32 - (sh))))

/* Family Key FK */
static const ut32 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

/* SM4 S-boxes */
static const ut8 Sbox[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/* Calculating next round keys */
R_API ut32 sm4_RK(ut32 rk) {
	ut8 a[4];
	ut8 b[4];
	ut32 lb = 0;

	r_write_be32 (a, rk);
	b[0] = Sbox[a[0]];
	b[1] = Sbox[a[1]];
	b[2] = Sbox[a[2]];
	b[3] = Sbox[a[3]];
	lb = r_read_be32 (b);

	return lb ^ (ROTL (lb, 13)) ^ (ROTL (lb, 23));
}

/* Permutations T */
static ut32 sm4_T(ut32 x) {
	ut8 a[4];
	ut8 b[4];
	ut32 lb = 0;

	r_write_be32 (a, x);
	b[0] = Sbox[a[0]];
	b[1] = Sbox[a[1]];
	b[2] = Sbox[a[2]];
	b[3] = Sbox[a[3]];
	lb = r_read_be32 (b);

	/* Linear transform L */
	return lb ^ (ROTL (lb, 2)) ^ (ROTL (lb, 10)) ^ (ROTL (lb, 18)) ^ (ROTL (lb, 24));
}

/* SM4 round */
static void sm4_round(const ut32 *sk, const ut8 *input, ut8 *output) {
	int i = 0;
	ut32 tmp[36] = { 0 };

	tmp[0] = r_read_at_be32 (input, 0);
	tmp[1] = r_read_at_be32 (input, 4);
	tmp[2] = r_read_at_be32 (input, 8);
	tmp[3] = r_read_at_be32 (input, 12);
	while (i < 32) {
		/* Round F function */
		tmp[i + 4] = tmp[i] ^ sm4_T (tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3] ^ sk[i]);
		i++;
	}
	r_write_at_be32 (output, tmp[35], 0);
	r_write_at_be32 (output, tmp[34], 4);
	r_write_at_be32 (output, tmp[33], 8);
	r_write_at_be32 (output, tmp[32], 12);
}

static void sm4_crypt(const ut32 *sk, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	for (; buflen > 0; buflen -= BLOCK_SIZE) {
		sm4_round (sk, inbuf, outbuf);
		inbuf += BLOCK_SIZE;
		outbuf += BLOCK_SIZE;
	}
}

/* SM4 key schedule */
static bool sm4_init(RCryptoJob *cj, ut32 *sk, const ut8 *key, int keylen, int dir) {
	ut32 MK[4];
	ut32 k[36];
	int i = 0;

	if (keylen != SM4_KEY_SIZE) {
		return false;
	}

	MK[0] = r_read_at_be32 (key, 0);
	MK[1] = r_read_at_be32 (key, 4);
	MK[2] = r_read_at_be32 (key, 8);
	MK[3] = r_read_at_be32 (key, 12);
	k[0] = MK[0] ^ FK[0];
	k[1] = MK[1] ^ FK[1];
	k[2] = MK[2] ^ FK[2];
	k[3] = MK[3] ^ FK[3];
	for (i = 0; i < 32; i++) {
		k[i + 4] = k[i] ^ (sm4_RK (k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ sm4_CK[i]));

		if (dir == 0) {
			cj->sm4_sk[i] = k[i + 4];
		} else {
			cj->sm4_sk[31 - i] = k[i + 4];
		}
	}
	return true;
}

static bool sm4_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->dir = direction;
	return sm4_init (cj, cj->sm4_sk, key, keylen, direction);
}

static int sm4_get_key_size(RCryptoJob *cry) {
	return SM4_KEY_SIZE;
}

static bool sm4_check(const char *algo) {
	return !strcmp (algo, "sm4-ecb");
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	r_return_val_if_fail (cj&& buf, false);
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	/* SM4 encryption or decryption */
	sm4_crypt (cj->sm4_sk, buf, obuf, len);
	r_crypto_job_append (cj, obuf, len);
	free (obuf);
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RCryptoPlugin r_crypto_plugin_sm4 = {
	.name = "sm4-ecb",
	.author = "Sylvain Pelissier",
	.license = "LGPL3",
	.set_key = sm4_set_key,
	.get_key_size = sm4_get_key_size,
	.check = sm4_check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_sm4,
	.version = R2_VERSION
};
#endif
