/* radare - LGPL - Copyright 2017 - deroad */

#include <r_lib.h>
#include <r_crypto.h>

#define DES_KEY_SIZE 8
#define BLOCK_SIZE 8
#define ROTL28(rs, sh) ((((rs) << (sh)) | ((rs) >> (28 - (sh)))) & 0x0FFFFFFF) // left 28
#define ROTL(rs, sh) (((rs) << (sh)) | ((rs) >> (32 - (sh)))) // left 32
#define ROTR(rs, sh) (((rs) >> (sh)) | ((rs) << (32 - (sh)))) // right 32

struct des_state {
	ut32 keylo[16]; // round key low
	ut32 keyhi[16]; // round key hi
	ut32 buflo; // buf low
	ut32 bufhi; // buf hi
	int key_size;
	int rounds;
	int i;
};

/* des sboxes */
static const ut32 sbox1[64] = {
	0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
	0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
	0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
	0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
	0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
	0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
	0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
	0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const ut32 sbox2[64] = {
	0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
	0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
	0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
	0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
	0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
	0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
	0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
	0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const ut32 sbox3[64] = {
	0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
	0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
	0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
	0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
	0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
	0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
	0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
	0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const ut32 sbox4[64] = {
	0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
	0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
	0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
	0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
	0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
	0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
	0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const ut32 sbox5[64] = {
	0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
	0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
	0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
	0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
	0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
	0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
	0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
	0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const ut32 sbox6[64] = {
	0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
	0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
	0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
	0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
	0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
	0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
	0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
	0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const ut32 sbox7[64] = {
	0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
	0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
	0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
	0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
	0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
	0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
	0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
	0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const ut32 sbox8[64] = {
	0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
	0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
	0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
	0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
	0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
	0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
	0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
	0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000
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

static void des_permute_key (ut32 *keylo, ut32 *keyhi) {
	ut32 perm;
	perm = ((*keylo >> 4) ^ *keyhi) & 0x0F0F0F0F;
	*keyhi ^= perm; *keylo ^= (perm << 4);
	perm = ((*keyhi >> 16) ^ *keylo) & 0x0000FFFF;
	*keylo ^= perm; *keyhi ^= (perm << 16);
	perm = ((*keylo >> 2) ^ *keyhi) & 0x33333333;
	*keyhi ^= perm; *keylo ^= (perm << 2);
	perm = ((*keyhi >> 16) ^ *keylo) & 0x0000FFFF;
	*keylo ^= perm; *keyhi ^= (perm << 16);
	perm = ((*keylo >> 1) ^ *keyhi) & 0x55555555;
	*keyhi ^= perm; *keylo ^= (perm << 1);
	perm = ((*keyhi >> 8) ^ *keylo) & 0x00FF00FF;
	*keylo ^= perm; *keyhi ^= (perm << 8);
	perm = ((*keylo >> 1) ^ *keyhi) & 0x55555555;
	*keyhi ^= perm; *keylo ^= (perm << 1);
	perm = (*keylo << 8) | ((*keyhi >> 20) & 0x000000F0);
	*keylo = ((*keyhi << 20) & 0x0FF00000);
	*keylo |= ((*keyhi << 4) & 0x000FF000);
	*keylo |= ((*keyhi >> 12) & 0x00000FF0);
	*keylo |= ((*keyhi >> 28) & 0x0000000F);
	*keyhi = perm >> 4;
}

// first permutation of the block
static void des_permute_block0  (ut32 *blocklo, ut32 *blockhi) {
	ut32 lo, hi, perm;
	if (!blocklo || !blockhi) {
		return;
	}
	lo = *blocklo;
	hi = *blockhi;
	perm = ((lo >> 4) ^ hi) & 0x0F0F0F0F;
	hi ^= perm; lo ^= perm << 4;
	perm = ((lo >> 16) ^ hi) & 0x0000FFFF;
	hi ^= perm; lo ^= perm << 16;
	perm = ((hi >> 2) ^ lo) & 0x33333333;
	lo ^= perm; hi ^= perm << 2;
	perm = ((hi >> 8) ^ lo) & 0x00FF00FF;
	lo ^= perm; hi ^= perm << 8;
	perm = ((lo >> 1) ^ hi) & 0x55555555;
	hi ^= perm; lo ^= perm << 1;
	*blocklo = ROTL(lo, 1);
	*blockhi = ROTL(hi, 1);
}

// last permutation of the block
static void des_permute_block1 (ut32 *blocklo, ut32 *blockhi) {
	ut32 lo, hi, perm;
	if (!blocklo || !blockhi) return;
	lo = *blocklo;
	hi = *blockhi;
	lo = ROTR(lo, 1);
	hi = ROTR(hi, 1);
	perm = ((lo >> 1) ^ hi) & 0x55555555;
	hi ^= perm; lo ^= perm << 1;
	perm = ((hi >> 8) ^ lo) & 0x00FF00FF;
	lo ^= perm; hi ^= perm << 8;
	perm = ((hi >> 2) ^ lo) & 0x33333333;
	lo ^= perm; hi ^= perm << 2;
	perm = ((lo >> 16) ^ hi) & 0x0000FFFF;
	hi ^= perm; lo ^= perm << 16;
	perm = ((lo >> 4) ^ hi) & 0x0F0F0F0F;
	hi ^= perm; lo ^= perm << 4;
	*blocklo = lo;
	*blockhi = hi;
}

// keylo & keyhi are the derivated round keys
// deskeylo & deskeyhi are the des derivated keys
static void des_round_key(int i, ut32 *keylo, ut32 *keyhi, ut32 *deskeylo, ut32 *deskeyhi) {
	ut32 deslo, deshi;
	if (!keylo || !keyhi || !deskeylo || !deskeyhi) return;
	if (i == 0 || i == 1 || i == 8 || i == 15) {
		*deskeylo = ROTL28(*deskeylo, 1);
		*deskeyhi = ROTL28(*deskeyhi, 1);
	} else {
		*deskeylo = ROTL28(*deskeylo, 2);
		*deskeyhi = ROTL28(*deskeyhi, 2);
	}

	deslo = *deskeylo;
	deshi = *deskeyhi;

	*keylo =((deslo << 4)  & 0x24000000) | ((deslo << 28) & 0x10000000) |
			((deslo << 14) & 0x08000000) | ((deslo << 18) & 0x02080000) |
			((deslo << 6)  & 0x01000000) | ((deslo << 9)  & 0x00200000) |
			((deslo >> 1)  & 0x00100000) | ((deslo << 10) & 0x00040000) |
			((deslo << 2)  & 0x00020000) | ((deslo >> 10) & 0x00010000) |
			((deshi >> 13) & 0x00002000) | ((deshi >> 4)  & 0x00001000) |
			((deshi << 6)  & 0x00000800) | ((deshi >> 1)  & 0x00000400) |
			((deshi >> 14) & 0x00000200) | ((deshi)	   & 0x00000100) |
			((deshi >> 5)  & 0x00000020) | ((deshi >> 10) & 0x00000010) |
			((deshi >> 3)  & 0x00000008) | ((deshi >> 18) & 0x00000004) |
			((deshi >> 26) & 0x00000002) | ((deshi >> 24) & 0x00000001);

	*keyhi =((deslo << 15) & 0x20000000) | ((deslo << 17) & 0x10000000) |
			((deslo << 10) & 0x08000000) | ((deslo << 22) & 0x04000000) |
			((deslo >> 2)  & 0x02000000) | ((deslo << 1)  & 0x01000000) |
			((deslo << 16) & 0x00200000) | ((deslo << 11) & 0x00100000) |
			((deslo << 3)  & 0x00080000) | ((deslo >> 6)  & 0x00040000) |
			((deslo << 15) & 0x00020000) | ((deslo >> 4)  & 0x00010000) |
			((deshi >> 2)  & 0x00002000) | ((deshi << 8)  & 0x00001000) |
			((deshi >> 14) & 0x00000808) | ((deshi >> 9)  & 0x00000400) |
			((deshi)	   & 0x00000200) | ((deshi << 7)  & 0x00000100) |
			((deshi >> 7)  & 0x00000020) | ((deshi >> 3)  & 0x00000011) |
			((deshi << 2)  & 0x00000004) | ((deshi >> 21) & 0x00000002);
}

static void des_round(ut32 *buflo, ut32 *bufhi, ut32 *roundkeylo, ut32 *roundkeyhi) {
	ut32 perm, lo, hi;
	if (!buflo || !bufhi || !roundkeylo || !roundkeyhi) return;
	lo = *buflo;
	hi = *bufhi;
	perm = hi ^ (*roundkeylo);
	lo ^= sbox2[(perm >> 24) & 0x3F];
	lo ^= sbox4[(perm >> 16) & 0x3F];
	lo ^= sbox6[(perm >> 8) & 0x3F];
	lo ^= sbox8[perm & 0x3F];
	perm = ROTR(hi, 4) ^ (*roundkeyhi);
	lo ^= sbox1[(perm >> 24) & 0x3F];
	lo ^= sbox3[(perm >> 16) & 0x3F];
	lo ^= sbox5[(perm >> 8) & 0x3F];
	lo ^= sbox7[perm & 0x3F];
	perm = hi;
	*bufhi = lo;
	*buflo = perm;
}

static int des_encrypt (struct des_state *st, const ut8 *input, ut8 *output) {
	if (!st || !input || !output) return false;
	st->buflo = be32 (input + 0);
	st->bufhi = be32 (input + 4);
 
	//first permutation
	des_permute_block0 (&st->buflo, &st->bufhi);

 	for (st->i = 0; st->i < 16; st->i++) {
	   des_round (&st->buflo, &st->bufhi, &st->keylo[st->i], &st->keyhi[st->i]);
	}
 	//last permutation
	des_permute_block1 (&st->bufhi, &st->buflo);
 
	//result
	wbe32 (output + 0, st->bufhi);
	wbe32 (output + 4, st->buflo);

	return true;
}

static int des_decrypt (struct des_state *st, const ut8 *input, ut8 *output) {
	if (!st || !input || !output) return false;
	st->buflo = be32 (input + 0);
	st->bufhi = be32 (input + 4);
	//first permutation
	des_permute_block0 (&st->buflo, &st->bufhi);

	for (st->i = 0; st->i < 16; st->i++) {
	   des_round (&st->buflo, &st->bufhi, &st->keylo[15 - st->i], &st->keyhi[15 - st->i]);
	}

	//last permutation
	des_permute_block1 (&st->bufhi, &st->buflo);
	//result
	wbe32 (output + 0, st->bufhi);
	wbe32 (output + 4, st->buflo);
	return true;
}


static struct des_state st;
static bool doEncrypt = true;

static bool des_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, bool direction) {
	ut32 keylo, keyhi, i;
	if (keylen != DES_KEY_SIZE) {
		return false;
	}
	// splitting the key in hi & lo
	keylo = be32 (key);
	keyhi = be32 (key + 4);

	st.key_size = DES_KEY_SIZE;
	st.rounds = 16;
	doEncrypt = direction == 0;
	// key permutation to derive round keys
	des_permute_key (&keylo, &keyhi);

	for (i = 0; i < 16; ++i) {
		// filling round keys space
		des_round_key (i, &st.keylo[i], &st.keyhi[i], &keylo, &keyhi);
	}

	return true;
}

static int des_get_key_size (RCrypto *cry) {
	return st.key_size;
}

static bool des_use (const char *algo) {
	return !strcmp (algo, "des-ecb");
}

static bool update (RCrypto *cry, const ut8 *buf, int len) {
	if (len <= 0) {
		return false;
	}

	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;

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
//	if (diff) {
//		ibuf[len] = 8; //0b1000;
//	}

	int i;
	if (doEncrypt) {
		for (i = 0; i < blocks; i++) {
			ut32 next = (BLOCK_SIZE * i);
			des_encrypt (&st, ibuf + next, obuf + next);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			ut32 next = (BLOCK_SIZE * i);
			des_decrypt (&st, ibuf + next, obuf + next);
		}
	}

	r_crypto_append (cry, obuf, size);
	free (obuf);
	free (ibuf);
	return 0;
}

static bool final (RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_des = {
	.name = "des-ecb",
	.set_key = des_set_key,
	.get_key_size = des_get_key_size,
	.use = des_use,
	.update = update,
	.final = final
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_des,
	.version = R2_VERSION
};
#endif
