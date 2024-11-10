/* radare2 - LGPL - Copyright 2022 - pancake,siguza */
// Ripped from https://github.com/Siguza/iometa/blob/master/src/cxx.c

#include <r_hash.h>

#define ROTL(x, b) (ut64)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do { \
		v0 += v1;               \
		v1 = ROTL(v1, 13) ^ v0; \
		v0 = ROTL(v0, 32);      \
		v2 += v3;               \
		v3 = ROTL(v3, 16) ^ v2; \
		v0 += v3;               \
		v3 = ROTL(v3, 21) ^ v0; \
		v2 += v1;               \
		v1 = ROTL(v1, 17) ^ v2; \
		v2 = ROTL(v2, 32);      \
	} while (0)

R_API ut64 r_hash_sip(const ut8 *in, ut64 inlen) {
	/* 	SipHash-2-4 using the key:
		0xb5d4c9eb79104a796fec8b1b428781d4 (big-endian)
	*/
	const ut8 *end;
	// v0 = k0 ^ 0x736f6d6570736575
	ut64 v0 = 0x0a257d1c9bbab1c0ULL;
	// v1 = k1 ^ 0x646f72616e646f6d
	ut64 v1 = 0xb0eef52375ef8302ULL;
	// v2 = k0 ^ 0x6c7967656e657261
	ut64 v2 = 0x1533771c85aca6d4ULL;
	// v3 = k1 ^ 0x7465646279746573
	ut64 v3 = 0xa0e4e32062ff891cULL;
	for (end = in + (inlen & ~7ULL); in != end; in += 8) {
		ut64 m = ((ut64)in[7] << 56)
			| ((ut64)in[6] << 48)
			| ((ut64)in[5] << 40)
			| ((ut64)in[4] << 32)
			| ((ut64)in[3] << 24)
			| ((ut64)in[2] << 16)
			| ((ut64)in[1] <<  8)
			| ((ut64)in[0]);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
	ut64 b = inlen << 56;
	switch (inlen & 7) {
	case 7: b |= (ut64)in[6] << 48;
	case 6: b |= (ut64)in[5] << 40;
	case 5: b |= (ut64)in[4] << 32;
	case 4: b |= (ut64)in[3] << 24;
	case 3: b |= (ut64)in[2] << 16;
	case 2: b |= (ut64)in[1] <<  8;
	case 1: b |= (ut64)in[0];
	case 0: break;
	}
	v3 ^= b;
	SIPROUND;
	SIPROUND;
	v0 ^= b;
	v2 ^= 0xff;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	return v0 ^ v1 ^ v2 ^ v3;
}
