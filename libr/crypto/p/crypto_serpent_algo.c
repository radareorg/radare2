#include "crypto_serpent_algo.h"

static const ut8 S[][16] = {
	{ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	{15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	{ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	{ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	{ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	{15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	{ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	{ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
};

static const ut8 Sinv[][16] = {
	{13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	{ 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	{12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	{ 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	{ 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	{ 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	{15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	{ 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
};

static const ut8 IPTable[] = {
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127
};

static const ut8 FPTable[] = {
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127
};

static inline void rotr(ut32 *x, int s) {
	*x = (*x >> s) | (*x << (32 - s));
}

static inline void rotl(ut32 *x, int s) {
	*x = (*x << s) | (*x >> (32 - s));
}

/* Apply SBox to the four least significant bits */
static inline ut8 apply_sbox(int si, ut8 x) {
	x = S[si][x & 0xf];
	return x;
}
/* Apply SBox to the four least significant bits */
static inline ut8 apply_sbox_inv(int si, ut8 x) {
	x = Sinv[si][x & 0xf];
	return x;
}

static inline ut8 get_bit(int i, ut32 input) {
	if (i >= 32) {
		eprintf("Wrong bit asked");
		exit(1);
	}
	return (input >> i) & 1;
}

void apply_IP(ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]) {
	int index;
	int i;
	for (i = 0; i < DW_BY_BLOCK * 32; i++) {
		index = IPTable[i];
		out[i / 32] ^= (-(ut32)get_bit (index % 32, in[index / 32]) ^ out[i / 32])
			& (1 << (i & 0x1f));
	}
}

void apply_FP(ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]) {
	int index;
	int i;
	for (i = 0; i < DW_BY_BLOCK * 32; i++) {
		index = FPTable[i];
		out[i / 32] ^= (-(ut32)get_bit (index % 32, in[index / 32]) ^ out[i / 32])
			& (1 << (i & 0x1f));
	}
}

void serpent_keyschedule(struct serpent_state st,
		ut32 subkeys[NB_SUBKEYS * DW_BY_BLOCK]) {
	if ((st.key_size != 128) && (st.key_size != 192) 
			&& (st.key_size != 256)) {
		eprintf ("Invalid key size");
		exit (1);
	}

	ut32 tmpkeys[DW_BY_BLOCK * NB_SUBKEYS + DW_BY_USERKEY] = {0};
	const ut32 phi = 0x9e3779b9;
	int si;
	ut8 in, out;
	int i, j, l;

	for (i = 0; i < st.key_size / 32; i++) {
		tmpkeys[i] = st.key[i];
	}

	// Padding key
	if (st.key_size != 256) {
		tmpkeys[st.key_size / 32] = 1;
	}

	for (i = DW_BY_USERKEY; i < NB_SUBKEYS * DW_BY_BLOCK + DW_BY_USERKEY; i++) {
		tmpkeys[i] = tmpkeys[i - 8] ^ tmpkeys[i - 5] ^ tmpkeys[i - 3] ^ tmpkeys[i - 1]
			^ phi ^ (i - 8);
		rotl (tmpkeys + i, 11);
	}

	// Applying sbox for subkey i
	for (i = 0; i < NB_SUBKEYS; i++) {
		si = (32 + 3 - i) % 8;

		// Iterates over all nibbles of the subkey i
		for (j = 0; j < NIBBLES_BY_SUBKEY; j++) {
			in = get_bit (j, tmpkeys[0 + DW_BY_BLOCK * i + DW_BY_USERKEY])
				| get_bit (j, tmpkeys[1 + DW_BY_BLOCK * i + DW_BY_USERKEY]) << 1
				| get_bit (j, tmpkeys[2 + DW_BY_BLOCK * i + DW_BY_USERKEY]) << 2
				| get_bit (j, tmpkeys[3 + DW_BY_BLOCK * i + DW_BY_USERKEY]) << 3;
			out = apply_sbox (si, in);
			for (l = 0; l < DW_BY_BLOCK; l++) {
				subkeys[l + DW_BY_BLOCK * i] |= get_bit (l, (ut32)out) << j;
			}
		}
	}

	// Apply IP on every subkey
	for (i = 0; i < NB_SUBKEYS; i++) {
		apply_IP (&subkeys[i * DW_BY_BLOCK], 
				&tmpkeys[DW_BY_USERKEY + i * DW_BY_BLOCK]);
	}

	memcpy (subkeys, tmpkeys + DW_BY_USERKEY, 132 * sizeof(ut32));
}

void apply_xor(ut32 block[DW_BY_BLOCK], ut32 subkey[DW_BY_BLOCK]) {
	int i;
	for (i = 0; i < DW_BY_BLOCK; i++) {
		block[i] ^= subkey[i];
	}
}

void apply_permut(ut32 block[DW_BY_BLOCK]) {
	ut32 tmp_block[DW_BY_BLOCK] = {0};
	apply_FP (block, tmp_block);
	rotl (tmp_block + 0, 13);
	rotl (tmp_block + 2, 3); 
	tmp_block[1] ^= tmp_block[0] ^ tmp_block[2];
	tmp_block[3] ^= tmp_block[2] ^ (tmp_block[0] << 3);
	rotl (tmp_block + 1, 1);
	rotl (tmp_block + 3, 7);
	tmp_block[0] ^= tmp_block[1] ^ tmp_block[3];
	tmp_block[2] ^= tmp_block[3] ^ (tmp_block[1] << 7);
	rotl (tmp_block + 0, 5);
	rotl (tmp_block + 2, 22);
	apply_IP (tmp_block, block);
}

void apply_permut_inv(ut32 block[DW_BY_BLOCK]) {
	ut32 tmp_block[DW_BY_BLOCK] = {0};
	apply_FP (block, tmp_block);
	rotr (tmp_block + 0, 5);
	rotr (tmp_block + 2, 22);
	tmp_block[2] ^= tmp_block[3] ^ (tmp_block[1] << 7);
	tmp_block[0] ^= tmp_block[1] ^ tmp_block[3];
	rotr (tmp_block + 3, 7);
	rotr (tmp_block + 1, 1);
	tmp_block[3] ^= tmp_block[2] ^ (tmp_block[0] << 3);
	tmp_block[1] ^= tmp_block[0] ^ tmp_block[2];
	rotr (tmp_block + 2, 3); 
	rotr (tmp_block + 0, 13);
	apply_IP (tmp_block, block);
}

void apply_round(int round, ut32 block[DW_BY_BLOCK], 
		ut32 subkeys[DW_BY_BLOCK*NB_SUBKEYS]) {
	int i, j;

	apply_xor (block, subkeys + 4 * round);

	for (i = 0; i < DW_BY_BLOCK; i++) {
		ut32 res = 0; 
		for (j = 0; j < 8; j++) {
			res |= apply_sbox (round % 8, (block[i] >> 4 * j) & 0xf) << 4 * j;
		}
		block[i] = res;
	}

	if (round == NB_ROUNDS - 1) {
		apply_xor (block, subkeys + 4 * (round + 1));
	} else {
		apply_permut (block);
	}
}

void apply_round_inv(int round, ut32 block[DW_BY_BLOCK], 
		ut32 subkeys[DW_BY_BLOCK*NB_SUBKEYS]) {
	if (round == NB_ROUNDS - 1) {
		apply_xor (block, subkeys + 4 * (round + 1));
	} else {
		apply_permut_inv (block);
	}

	int i, j;
	ut32 res;

	for (i = 0; i < DW_BY_BLOCK; i++) {
		res = 0; 
		for (j = 0; j < 8; j++) {
			res |= apply_sbox_inv (round%8, (block[i] >> 4 * j) & 0xf) << 4 * j;
		}
		block[i] = res;
	}

	apply_xor (block, subkeys + 4 * round);
}

void serpent_encrypt(struct serpent_state *st, ut32 in[DW_BY_BLOCK], 
		ut32 out[DW_BY_BLOCK]) {
	int i;
	ut32 subkeys[DW_BY_BLOCK * NB_SUBKEYS] = {0};
	ut32 tmp_block[DW_BY_BLOCK] = {0};

	serpent_keyschedule (*st, subkeys);

	apply_IP (in, tmp_block);
	for (i = 0; i < NB_ROUNDS; i++) {
		apply_round(i, tmp_block, subkeys);
	}
	apply_FP (tmp_block, out);
}



void serpent_decrypt(struct serpent_state *st, ut32 in[DW_BY_BLOCK],
		ut32 out[DW_BY_BLOCK]) {
	int i;
	ut32 subkeys[DW_BY_BLOCK * NB_SUBKEYS] = {0};
	ut32 tmp_block[DW_BY_BLOCK] = {0};

	serpent_keyschedule (*st, subkeys);

	apply_IP (in, tmp_block);
	for (i = NB_ROUNDS - 1; i >= 0; i--) {
		apply_round_inv (i, tmp_block, subkeys);
	}
	apply_FP (tmp_block, out);
}
