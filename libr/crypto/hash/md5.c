/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 *
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All rights reserved.
 * Code cleanup by pancake @ 2017
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#include <r_hash.h>

/* F, G, H and I are basic MD5 functions.  */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// ROTATE_LEFT rotates x left n bits.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation. */
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F ((b), (c), (d)) + (x) + (ut32)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
	(a) += G ((b), (c), (d)) + (x) + (ut32)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
	(a) += H ((b), (c), (d)) + (x) + (ut32)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
	(a) += I ((b), (c), (d)) + (x) + (ut32)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}

/* Encodes input (ut32) into output (ut8). Assumes len is a multiple of 4. */
static void encode(ut8 *output, ut32 *input, ut32 len) {
	ut32 i, j;
	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (ut8)(input[i] & 0xff);
		output[j+1] = (ut8)((input[i] >> 8) & 0xff);
		output[j+2] = (ut8)((input[i] >> 16) & 0xff);
		output[j+3] = (ut8)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (ut8) into output (ut32). Assumes len is a multiple of 4 */
static void decode(ut32 *output, const ut8 *input, ut32 len) {
	ut32 i, j;
	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[i] = ((ut32)input[j]) | (((ut32)input[j + 1]) << 8) |
			    (((ut32)input[j + 2]) << 16) |
			    (((ut32)input[j + 3]) << 24);
	}
}

/* MD5 basic transformation. Transforms state based on block */
static void MD5Transform(ut32 state[4], const ut8 block[64]) {
	ut32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	decode (x, block, 64);

	/* Round 1 */
	FF (a, b, c, d, x[ 0], 7, 0xd76aa478);
	FF (d, a, b, c, x[ 1], 12, 0xe8c7b756);
	FF (c, d, a, b, x[ 2], 17, 0x242070db);
	FF (b, c, d, a, x[ 3], 22, 0xc1bdceee);
	FF (a, b, c, d, x[ 4], 7, 0xf57c0faf);
	FF (d, a, b, c, x[ 5], 12, 0x4787c62a);
	FF (c, d, a, b, x[ 6], 17, 0xa8304613);
	FF (b, c, d, a, x[ 7], 22, 0xfd469501);
	FF (a, b, c, d, x[ 8], 7, 0x698098d8);
	FF (d, a, b, c, x[ 9], 12, 0x8b44f7af);
	FF (c, d, a, b, x[10], 17, 0xffff5bb1);
	FF (b, c, d, a, x[11], 22, 0x895cd7be);
	FF (a, b, c, d, x[12], 7, 0x6b901122);
	FF (d, a, b, c, x[13], 12, 0xfd987193);
	FF (c, d, a, b, x[14], 17, 0xa679438e);
	FF (b, c, d, a, x[15], 22, 0x49b40821);

	/* Round 2 */
	GG (a, b, c, d, x[ 1], 5, 0xf61e2562);
	GG (d, a, b, c, x[ 6], 9, 0xc040b340);
	GG (c, d, a, b, x[11], 14, 0x265e5a51);
	GG (b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
	GG (a, b, c, d, x[ 5], 5, 0xd62f105d);
	GG (d, a, b, c, x[10], 9,  0x2441453);
	GG (c, d, a, b, x[15], 14, 0xd8a1e681);
	GG (b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
	GG (a, b, c, d, x[ 9], 5, 0x21e1cde6);
	GG (d, a, b, c, x[14], 9, 0xc33707d6);
	GG (c, d, a, b, x[ 3], 14, 0xf4d50d87);
	GG (b, c, d, a, x[ 8], 20, 0x455a14ed);
	GG (a, b, c, d, x[13], 5, 0xa9e3e905);
	GG (d, a, b, c, x[ 2], 9, 0xfcefa3f8);
	GG (c, d, a, b, x[ 7], 14, 0x676f02d9);
	GG (b, c, d, a, x[12], 20, 0x8d2a4c8a);

	/* Round 3 */
	HH (a, b, c, d, x[ 5], 4, 0xfffa3942);
	HH (d, a, b, c, x[ 8], 11, 0x8771f681);
	HH (c, d, a, b, x[11], 16, 0x6d9d6122);
	HH (b, c, d, a, x[14], 23, 0xfde5380c);
	HH (a, b, c, d, x[ 1], 4, 0xa4beea44);
	HH (d, a, b, c, x[ 4], 11, 0x4bdecfa9);
	HH (c, d, a, b, x[ 7], 16, 0xf6bb4b60);
	HH (b, c, d, a, x[10], 23, 0xbebfbc70);
	HH (a, b, c, d, x[13], 4, 0x289b7ec6);
	HH (d, a, b, c, x[ 0], 11, 0xeaa127fa);
	HH (c, d, a, b, x[ 3], 16, 0xd4ef3085);
	HH (b, c, d, a, x[ 6], 23,  0x4881d05);
	HH (a, b, c, d, x[ 9], 4, 0xd9d4d039);
	HH (d, a, b, c, x[12], 11, 0xe6db99e5);
	HH (c, d, a, b, x[15], 16, 0x1fa27cf8);
	HH (b, c, d, a, x[ 2], 23, 0xc4ac5665);

	/* Round 4 */
	II (a, b, c, d, x[ 0], 6, 0xf4292244);
	II (d, a, b, c, x[ 7], 10, 0x432aff97);
	II (c, d, a, b, x[14], 15, 0xab9423a7);
	II (b, c, d, a, x[ 5], 21, 0xfc93a039);
	II (a, b, c, d, x[12], 6, 0x655b59c3);
	II (d, a, b, c, x[ 3], 10, 0x8f0ccc92);
	II (c, d, a, b, x[10], 15, 0xffeff47d);
	II (b, c, d, a, x[ 1], 21, 0x85845dd1);
	II (a, b, c, d, x[ 8], 6, 0x6fa87e4f);
	II (d, a, b, c, x[15], 10, 0xfe2ce6e0);
	II (c, d, a, b, x[ 6], 15, 0xa3014314);
	II (b, c, d, a, x[13], 21, 0x4e0811a1);
	II (a, b, c, d, x[ 4], 6, 0xf7537e82);
	II (d, a, b, c, x[11], 10, 0xbd3af235);
	II (c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
	II (b, c, d, a, x[ 9], 21, 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information. check if compiler optimizes out this */
	r_mem_zero ((void*)x, sizeof (x));
}

static const ut8 PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* MD5 initialization. Begins an MD5 operation, writing a new context */
void r_hash_md5_init(RHashMD5Context *context) {
	if (context) {
		context->count[0] = context->count[1] = 0;
		context->state[0] = 0x67452301;
		context->state[1] = 0xefcdab89;
		context->state[2] = 0x98badcfe;
		context->state[3] = 0x10325476;
	}
}

/* MD5 block update operation. Continues an MD5 message-digest operation,
 * processing another message block, and updating the context */
void r_hash_md5_update(RHashMD5Context *context, const ut8 *input, ut32 inputLen) {
	ut32 i;

	/* Compute number of bytes mod 64 */
	ut32 index = (ut32)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((ut32)inputLen << 3)) < ((ut32)inputLen << 3)) {
		context->count[1]++;
	}
	context->count[1] += ((ut32)inputLen >> 29);

	ut32 partLen = 64 - index;

	// Transform as many times as possible
	if (inputLen >= partLen) {
		memmove ((void*)&context->buffer[index], (void*)input, partLen);
		MD5Transform (context->state, context->buffer);
		for (i = partLen; i + 63 < inputLen; i += 64) {
			MD5Transform (context->state, &input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	// remaining input
	memmove ((void*)&context->buffer[index], (void*)&input[i], inputLen - i);
}

void r_hash_md5_final(ut8 digest[16], RHashMD5Context *context) {
	ut8 bits[8];

	/* Save number of bits */
	encode (bits, context->count, 8);

	/* Pad out to 56 mod 64.  */
	ut32 index = (ut32)((context->count[0] >> 3) & 0x3f);
	ut32 padLen = (index < 56) ? (56 - index) : (120 - index);
	r_hash_md5_update (context, PADDING, padLen);

	/* Append length (before padding) */
	r_hash_md5_update (context, bits, 8);

	/* Store state in digest */
	encode (digest, context->state, 16);

	/* Zeroize sensitive information.  */
	r_mem_zero ((void*)context, sizeof (*context));
}
