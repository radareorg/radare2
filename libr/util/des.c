#include <r_types.h>
#include <r_util.h>

static const ut32 IP[] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

static const ut32 INV_IP[] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

static const ut32 E[] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

static const ut32 P[] = {
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25,
};

static const ut32 SBOX1[] = {
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
};

static const ut32 SBOX2[] = {
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
};

static const ut32 SBOX3[] = {
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
};

static const ut32 SBOX4[] = {
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
};

static const ut32 SBOX5[] = {
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
};

static const ut32 SBOX6[] = {
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
};

static const ut32 SBOX7[] = {
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
};

static const ut32 SBOX8[] = {
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};

static const ut8 ROTL[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
static const ut8 ROTR[] = { 0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

const ut8 PC_1[] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

const ut8 PC_2[] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

ut64 des_rotl (ut64 k, int round)
{
	ut32 r, l;
	r = k & 0xfffffff;
	l = (ut32)((ut64)(k & 0xfffffff0000000)>>28);
	k = 0LL;
	k |= ((((ut64)r << ROTL[round&0xf]) | (r >> (28 - ROTL[round&0xf]))) & 0xfffffff);
	k |= ((ut64)((((ut64)l << ROTL[round&0xf]) | ((ut64)l >> (28 - ROTL[round&0xf]))) & 0xfffffff)<<28);
	return k;
}

ut64 des_rotr (ut64 k, int round)
{
	ut32 r, l;
	r = k & 0xfffffff;
	l = (ut32)(((ut64)(k & 0xfffffff0000000))>>28);
	k = 0LL;
	k |= (((r >> ROTR[round&0xf]) | (r << (28 - ROTR[round & 0xf]))) & 0xfffffff);
	k |= ((ut64)(((l >> ROTR[round&0xf]) | (l << (28 - ROTR[round & 0xf]))) & 0xfffffff)<<28);
	return k;
}

R_API ut64 r_des_get_roundkey (ut64 key, int round, int enc) {
	ut64 rk = r_des_pc1 (key);
	int i;
	if (enc) {
		for (i = 0; i < round; i++)
			rk = des_rotl (rk, i);
		return r_des_pc2 (rk);
	}
	for (i = 0; i < round; i++)
		rk = des_rotr (rk, i);
	return r_des_pc2 (rk);
}

R_API ut64 r_des_pc1 (ut64 k)
{
	int i;
	ut64 ret_key = 0LL;
	for (i=0; i < 56; i++) {
		ret_key |= ((ut64)((k & ((ut64)0x1 << (PC_1[i]-1))) >> (PC_1[i]-1)) << i);
	}
	return ret_key;
}

R_API ut64 r_des_pc2 (ut64 k)
{
	int i;
	ut64 ret_key = 0LL;
	for (i=0; i<48; i++)
		ret_key |= ((ut64)((k & ((ut64)0x1 << (PC_2[i]-1))) >> (PC_2[i]-1)) << i);
	return ret_key;
}

R_API ut64 r_des_round (ut64 plaintext, ut64 round_key) {
	ut64 state = r_des_ip (plaintext, 0);
	ut32 r = state & 0xffffffff;
	ut32 l = (state & 0xffffffff00000000ull) >> 32;
	ut32 t = r_des_f(r,round_key);

	state = r;
	state = (state << 32) | (t ^ l);

	return r_des_ip(state,1);
}

R_API ut64 r_des_ip (ut64 state, int inv) {
	ut64 ret = 0;
	ut32 bit = 0;
	const ut32 *p = (inv ? INV_IP : IP);

	while(bit < 64) {
		ret |= (state & (1ul << (p[bit] - 1)) ? 1ul << bit : 0);
		bit += 1;
	}

	return ret;
}

R_API ut64 r_des_expansion (ut32 half) {
	ut64 ret = 0;
	ut32 bit = 0;

	while(bit < 48) {
		ret |= (half & (1ul << (E[bit] - 1)) ? 1ul << bit : 0);
		bit += 1;
	}

	return ret;
}

R_API ut32 r_des_p (ut32 half) {
	ut32 ret = 0;
	ut32 bit = 0;

	while(bit < 32) {
		ret |= (half & (1ul << (P[bit] - 1)) ? 1ul << bit : 0);
		bit += 1;
	}

	return ret;
}

R_API ut32 r_des_sbox (ut8 in, const ut32* box) {
	ut32 idx = (in & 1) | ((in & 32) >> 4);

	idx = idx * 16 + ((in >> 1) & 15);
	return box[idx];
}

R_API ut64 r_des_f (ut32 half, ut64 round_key) {
	ut64 t = r_des_expansion(half) ^ round_key;
	ut32 ret = 0;

	ret |= r_des_sbox((t >> 0) & 63,SBOX8) << 0;
	ret |= r_des_sbox((t >> 6) & 63,SBOX7) << 4;
	ret |= r_des_sbox((t >> 12) & 63,SBOX6) << 8;
	ret |= r_des_sbox((t >> 18) & 63,SBOX5) << 12;
	ret |= r_des_sbox((t >> 24) & 63,SBOX4) << 16;
	ret |= r_des_sbox((t >> 30) & 63,SBOX3) << 20;
	ret |= r_des_sbox((t >> 36) & 63,SBOX2) << 24;
	ret |= r_des_sbox((t >> 42) & 63,SBOX1) << 28;

	return r_des_p (ret);
}