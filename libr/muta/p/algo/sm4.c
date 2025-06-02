/* radare - LGPL - Copyright 2017-2025 - Sylvain Pelissier */
// Implementation of SM4 block cipher https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10

#include <r_muta.h>
#include <r_muta/r_sm4.h>
#include <r_util.h>
#include <memory.h>

/* Permutations T */
static ut32 sm4_T(ut32 x) {
	ut8 a[4];
	ut8 b[4];
	ut32 lb = 0;

	r_write_be32 (a, x);
	b[0] = sm4_sbox[a[0]];
	b[1] = sm4_sbox[a[1]];
	b[2] = sm4_sbox[a[2]];
	b[3] = sm4_sbox[a[3]];
	lb = r_read_be32 (b);

	/* Linear transform L */
	return lb ^ (SM4_ROTL (lb, 2)) ^ (SM4_ROTL (lb, 10)) ^ (SM4_ROTL (lb, 18)) ^ (SM4_ROTL (lb, 24));
}

/* SM4 round */
void sm4_round(const ut32 *sk, const ut8 *input, ut8 *output) {
	int i;
	ut32 tmp[36] = { 0 };

	tmp[0] = r_read_at_be32 (input, 0);
	tmp[1] = r_read_at_be32 (input, 4);
	tmp[2] = r_read_at_be32 (input, 8);
	tmp[3] = r_read_at_be32 (input, 12);
	for (i = 0; i < 32; i++) {
		/* Round F function */
		tmp[i + 4] = tmp[i] ^ sm4_T (tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3] ^ sk[i]);
	}
	r_write_at_be32 (output, tmp[35], 0);
	r_write_at_be32 (output, tmp[34], 4);
	r_write_at_be32 (output, tmp[33], 8);
	r_write_at_be32 (output, tmp[32], 12);
}

/* SM4 key schedule */
bool sm4_init(ut32 *sk, const ut8 *key, int keylen, int dir) {
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

		if (dir == R_CRYPTO_DIR_ENCRYPT) {
			sk[i] = k[i + 4];
		} else {
			sk[31 - i] = k[i + 4];
		}
	}
	return true;
}
