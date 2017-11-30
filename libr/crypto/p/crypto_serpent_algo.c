#include "crypto_serpent_algo.h"

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
	for (int i = 0; i < DW_BY_BLOCK*32; i++) {
		index = IPTable[i];
		out[i/32] ^= (-(ut32)get_bit(index%32, in[index/32])^out[i/32])
			& (1 << i);
	}
}

void apply_FP(ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]) {
	int index;
	for (int i = 0; i < DW_BY_BLOCK*32; i++) {
		index = FPTable[i];
		out[i/32] ^= (-(ut32)get_bit(index%32, in[index/32])^out[i/32])
			& (1 << i);
	}
}

void serpent_keyschedule(struct serpent_state st,
		ut32 subkeys[NB_SUBKEYS*DW_BY_BLOCK]) {
	if (st.key_size != 128 && st.key_size != 192 
			&& st.key_size != 256) {
		eprintf("Invalid key size");
		exit(1);
	}

	ut32 tmpkeys[DW_BY_BLOCK*NB_SUBKEYS+DW_BY_USERKEY] = {0};
	const ut32 phi = 0x9e3779b9;
	int si;
	ut8 in, out;

	for (int i = 0; i < st.key_size/32; i++) {
		tmpkeys[i] = st.key[i];
	}

	// Padding key
	if (st.key_size != 256) {
		tmpkeys[st.key_size/32] = 1;
	}

	for (int i=DW_BY_USERKEY; i < NB_SUBKEYS*DW_BY_BLOCK+DW_BY_USERKEY; i++) {
		tmpkeys[i] = tmpkeys[i-8]^tmpkeys[i-5]^tmpkeys[i-3]^tmpkeys[i-1]
			^phi^(i-8);
		rotl(&(tmpkeys[i]), 11);
	}

	// Applying sbox for subkey i
	for (int i = 0; i < NB_SUBKEYS; i++) {
		si = (32 + 3 - i) % 8;

		// Iterates over all nibbles of the subkey i
		for (int j = 0; j < NIBBLES_BY_SUBKEY; j++) {
			in = get_bit(j, tmpkeys[0+DW_BY_BLOCK*i+DW_BY_USERKEY])
				| get_bit(j, tmpkeys[1+DW_BY_BLOCK*i+DW_BY_USERKEY]) << 1
				| get_bit(j, tmpkeys[2+DW_BY_BLOCK*i+DW_BY_USERKEY]) << 2
				| get_bit(j, tmpkeys[3+DW_BY_BLOCK*i+DW_BY_USERKEY]) << 3;
			out = apply_sbox(si, in);
			for (int l = 0; l < DW_BY_BLOCK; l++) {
				subkeys[l+DW_BY_BLOCK*i] |= get_bit(l, (ut32)out) << j;
			}
		}
	}

	// Apply IP on every subkey
	for (int i = 0; i < NB_SUBKEYS; i++) {
		apply_IP(&(subkeys[i*DW_BY_BLOCK]), 
				&(tmpkeys[DW_BY_USERKEY + i*DW_BY_BLOCK]));
	}

	memcpy(subkeys, &(tmpkeys[DW_BY_USERKEY]), 132*sizeof(ut32));
}

void apply_xor(ut32 block[DW_BY_BLOCK], ut32 subkey[DW_BY_BLOCK]) {
	for (int i = 0; i < DW_BY_BLOCK; i++) {
		block[i] ^= subkey[i];
	}
}

void apply_permut(ut32 block[DW_BY_BLOCK]) {
	ut32 tmp_block[DW_BY_BLOCK] = {0};
	apply_FP(block, tmp_block);
	rotl(&tmp_block[0], 13);
	rotl(&tmp_block[2], 3); 
	tmp_block[1] ^= tmp_block[0]^tmp_block[2];
	tmp_block[3] ^= tmp_block[2]^(tmp_block[0]<<3);
	rotl(&tmp_block[1], 1);
	rotl(&tmp_block[3], 7);
	tmp_block[0] ^= tmp_block[1]^tmp_block[3];
	tmp_block[2] ^= tmp_block[3]^(tmp_block[1]<<7);
	rotl(&tmp_block[0], 5);
	rotl(&tmp_block[2], 22);
	apply_IP(tmp_block, block);
}

void apply_permut_inv(ut32 block[DW_BY_BLOCK]) {
	ut32 tmp_block[DW_BY_BLOCK] = {0};
	apply_FP(block, tmp_block);
	rotr(&tmp_block[0], 5);
	rotr(&tmp_block[2], 22);
	tmp_block[2] ^= tmp_block[3]^(tmp_block[1]<<7);
	tmp_block[0] ^= tmp_block[1]^tmp_block[3];
	rotr(&tmp_block[3], 7);
	rotr(&tmp_block[1], 1);
	tmp_block[3] ^= tmp_block[2]^(tmp_block[0]<<3);
	tmp_block[1] ^= tmp_block[0]^tmp_block[2];
	rotr(&tmp_block[2], 3); 
	rotr(&tmp_block[0], 13);
	apply_IP(tmp_block, block);
}

void apply_round(int round, ut32 block[DW_BY_BLOCK], 
		ut32 subkeys[DW_BY_BLOCK*NB_SUBKEYS]) {


	apply_xor(block, &(subkeys[4*round]));

	ut32 res;
	for (int i = 0; i < DW_BY_BLOCK; i++) {
		res = 0; 
		for (int j = 0; j < 8; j++) {
			res |= apply_sbox(round%8, (block[i] >> 4*j) & 0xf) << 4*j;
		}
		block[i] = res;
	}

	if (round == NB_ROUNDS - 1) {
		apply_xor(block, &(subkeys[4*(round+1)]));
	} else {
		apply_permut(block);
	}
}

void apply_round_inv(int round, ut32 block[DW_BY_BLOCK], 
		ut32 subkeys[DW_BY_BLOCK*NB_SUBKEYS]) {

	if (round == NB_ROUNDS - 1) {
		apply_xor(block, &(subkeys[4*(round+1)]));
	} else {
		apply_permut_inv(block);
	}

	ut32 res;
	for (int i = 0; i < DW_BY_BLOCK; i++) {
		res = 0; 
		for (int j = 0; j < 8; j++) {
			res |= apply_sbox_inv(round%8, (block[i] >> 4*j) & 0xf) << 4*j;
		}
		block[i] = res;
	}

	apply_xor(block, &(subkeys[4*round]));
}

void serpent_encrypt(struct serpent_state *st, ut32 in[DW_BY_BLOCK], 
		ut32 out[DW_BY_BLOCK]) {

	ut32 subkeys[DW_BY_BLOCK*NB_SUBKEYS] = {0};
	ut32 tmp_block[DW_BY_BLOCK] = {0};

	serpent_keyschedule(*st, subkeys);

	apply_IP(in, tmp_block);
	for (int i = 0; i < NB_ROUNDS; i++) {
		apply_round(i, tmp_block, subkeys);
	}
	apply_FP(tmp_block, out);
}



void serpent_decrypt(struct serpent_state *st, ut32 in[DW_BY_BLOCK],
		ut32 out[DW_BY_BLOCK]) {

	ut32 subkeys[DW_BY_BLOCK*NB_SUBKEYS] = {0};
	ut32 tmp_block[DW_BY_BLOCK] = {0};

	serpent_keyschedule(*st, subkeys);

	apply_IP(in, tmp_block);
	for (int i = NB_ROUNDS - 1; i >= 0; i--) {
		apply_round_inv(i, tmp_block, subkeys);
	}
	apply_FP(tmp_block, out);
}
