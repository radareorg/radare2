#if 0
Unix SMB/Netbios implementation.
Version 1.9.
a implementation of MD4 designed for use in the SMB authentication protocol
Copyright (C) Andrew Tridgell 1997-1998.
Modified by Steve French (sfrench@us.ibm.com) 2002-2003

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA
#endif

#include <r_hash.h>

#if WITH_GPL

static inline ut32 F(ut32 X, ut32 Y, ut32 Z) {
	return (X & Y) | ((~X) & Z);
}

static inline ut32 G(ut32 X, ut32 Y, ut32 Z) {
	return (X & Y) | (X & Z) | (Y & Z);
}

static inline ut32 H(ut32 X, ut32 Y, ut32 Z) {
	return X ^ Y ^ Z;
}

static inline ut32 lshift(ut32 x, int s) {
	x &= UT32_MAX;
	return ((x << s) & UT32_MAX) | (x >> (32 - s));
}

#define ROUND1(a, b, c, d, k, s) (*a) = lshift ((*a) + F (*b, *c, *d) + X[k], s)
#define ROUND2(a, b, c, d, k, s) (*a) = lshift ((*a) + G (*b, *c, *d) + X[k] + (ut32) 0x5A827999, s)
#define ROUND3(a, b, c, d, k, s) (*a) = lshift ((*a) + H (*b, *c, *d) + X[k] + (ut32) 0x6ED9EBA1, s)

/* this applies md4 to 64 byte chunks */
static void mdfour64(ut32 *M, ut32 *A, ut32 *B, ut32 *C, ut32 *D) {
	int j;
	ut32 X[16];

	for (j = 0; j < 16; j++) {
		X[j] = M[j];
	}

	ut32 AA = *A;
	ut32 BB = *B;
	ut32 CC = *C;
	ut32 DD = *D;

	ROUND1 (A, B, C, D, 0, 3);
	ROUND1 (D, A, B, C, 1, 7);
	ROUND1 (C, D, A, B, 2, 11);
	ROUND1 (B, C, D, A, 3, 19);
	ROUND1 (A, B, C, D, 4, 3);
	ROUND1 (D, A, B, C, 5, 7);
	ROUND1 (C, D, A, B, 6, 11);
	ROUND1 (B, C, D, A, 7, 19);
	ROUND1 (A, B, C, D, 8, 3);
	ROUND1 (D, A, B, C, 9, 7);
	ROUND1 (C, D, A, B, 10, 11);
	ROUND1 (B, C, D, A, 11, 19);
	ROUND1 (A, B, C, D, 12, 3);
	ROUND1 (D, A, B, C, 13, 7);
	ROUND1 (C, D, A, B, 14, 11);
	ROUND1 (B, C, D, A, 15, 19);

	ROUND2 (A, B, C, D, 0, 3);
	ROUND2 (D, A, B, C, 4, 5);
	ROUND2 (C, D, A, B, 8, 9);
	ROUND2 (B, C, D, A, 12, 13);
	ROUND2 (A, B, C, D, 1, 3);
	ROUND2 (D, A, B, C, 5, 5);
	ROUND2 (C, D, A, B, 9, 9);
	ROUND2 (B, C, D, A, 13, 13);
	ROUND2 (A, B, C, D, 2, 3);
	ROUND2 (D, A, B, C, 6, 5);
	ROUND2 (C, D, A, B, 10, 9);
	ROUND2 (B, C, D, A, 14, 13);
	ROUND2 (A, B, C, D, 3, 3);
	ROUND2 (D, A, B, C, 7, 5);
	ROUND2 (C, D, A, B, 11, 9);
	ROUND2 (B, C, D, A, 15, 13);

	ROUND3 (A, B, C, D, 0, 3);
	ROUND3 (D, A, B, C, 8, 9);
	ROUND3 (C, D, A, B, 4, 11);
	ROUND3 (B, C, D, A, 12, 15);
	ROUND3 (A, B, C, D, 2, 3);
	ROUND3 (D, A, B, C, 10, 9);
	ROUND3 (C, D, A, B, 6, 11);
	ROUND3 (B, C, D, A, 14, 15);
	ROUND3 (A, B, C, D, 1, 3);
	ROUND3 (D, A, B, C, 9, 9);
	ROUND3 (C, D, A, B, 5, 11);
	ROUND3 (B, C, D, A, 13, 15);
	ROUND3 (A, B, C, D, 3, 3);
	ROUND3 (D, A, B, C, 11, 9);
	ROUND3 (C, D, A, B, 7, 11);
	ROUND3 (B, C, D, A, 15, 15);

	*A += AA;
	*B += BB;
	*C += CC;
	*D += DD;

	*A &= UT32_MAX;
	*B &= UT32_MAX;
	*C &= UT32_MAX;
	*D &= UT32_MAX;

	for (j = 0; j < 16; j++) {
		X[j] = 0;
	}
}

static void copy64(ut32 *M, const ut8 *in) {
	int i;
	for (i = 0; i < 16; i++) {
		M[i] = ((ut32)in[i * 4 + 3] << 24) | (in[i * 4 + 2] << 16) |
		(in[i * 4 + 1] << 8) | (in[i * 4 + 0] << 0);
	}
}

static void copy4(ut8 *out, ut32 x) {
	out[0] = x & 0xFF;
	out[1] = (x >> 8) & 0xFF;
	out[2] = (x >> 16) & 0xFF;
	out[3] = (x >> 24) & 0xFF;
}

R_IPI void r_hash_md4(const ut8 *in, int n, ut8 *out) {
	ut8 buf[128];
	ut32 M[16];
	ut32 b = n * 8;
	int i;
	ut32 A = 0x67452301;
	ut32 B = 0xefcdab89;
	ut32 C = 0x98badcfe;
	ut32 D = 0x10325476;

	while (n > 64) {
		copy64 (M, in);
		mdfour64 (M, &A, &B, &C, &D);
		in += 64;
		n -= 64;
	}

	for (i = 0; i < 128; i++) {
		buf[i] = 0;
	}
	memcpy (buf, in, n);
	buf[n] = 0x80;

	if (n <= 55) {
		copy4 (buf + 56, b);
		copy64 (M, buf);
		mdfour64 (M, &A, &B, &C, &D);
	} else {
		copy4 (buf + 120, b);
		copy64 (M, buf);
		mdfour64 (M, &A, &B, &C, &D);
		copy64 (M, buf + 64);
		mdfour64 (M, &A, &B, &C, &D);
	}

	for (i = 0; i < 128; i++) {
		buf[i] = 0;
	}
	copy64 (M, buf);

	copy4 (out, A);
	copy4 (out + 4, B);
	copy4 (out + 8, C);
	copy4 (out + 12, D);

	A = B = C = D = 0;
}

#else
R_IPI void r_hash_md4(const ut8 *in, int n, ut8 *out) {
	R_LOG_ERROR ("md4 is only available on GPL builds");
}
#endif
