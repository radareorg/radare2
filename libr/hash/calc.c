/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include "r_hash.h"

#if 0
// TODO: move to r_util
static int bitnum(int bit) {
	int b;
	for(b=0;bit>>=1;b++);
	return b;
}
#endif

/* TODO: do it more beautiful with structs and not spaguetis */
/* TODO: find a better method name */
R_API int r_hash_calculate(struct r_hash_t *ctx, int algobit, const ut8 *buf, ut32 len) {
	if (algobit & R_HASH_MD4) {
		r_hash_do_md4(ctx, buf, len);
		return R_HASH_SIZE_MD4;
	}
	if (algobit & R_HASH_MD5) {
		r_hash_do_md5(ctx, buf, len);
		return R_HASH_SIZE_MD5;
	}
	if (algobit & R_HASH_SHA1) {
		r_hash_do_sha1(ctx, buf, len);
		return R_HASH_SIZE_SHA1;
	}
	if (algobit & R_HASH_SHA256) {
		r_hash_do_sha256(ctx, buf, len);
		return R_HASH_SIZE_SHA256;
	}
	if (algobit & R_HASH_SHA384) {
		r_hash_do_sha384(ctx, buf, len);
		return R_HASH_SIZE_SHA384;
	}
	if (algobit & R_HASH_SHA512) {
		r_hash_do_sha512(ctx, buf, len);
		return R_HASH_SIZE_SHA512;
	}
	if (algobit & R_HASH_PCPRINT) {
		ctx->digest[0] = r_hash_pcprint(buf, len);
		return 1;
	}
	if (algobit & R_HASH_PARITY) {
		ctx->digest[0] = r_hash_parity(buf, len);
		return 1;
	}
	if (algobit & R_HASH_ENTROPY) {
		ctx->digest[0] = (ut8)r_hash_entropy (buf, len);
		return 1;
	}
	if (algobit & R_HASH_XOR) {
		ctx->digest[0] = r_hash_xor(buf, len);
		return 1;
	}
	if (algobit & R_HASH_XORPAIR) {
		ut16 res = r_hash_xorpair(buf, len);
		memcpy(ctx->digest, &res, 2);
		return 2;
	}
	if (algobit & R_HASH_MOD255) {
		ctx->digest[0] = r_hash_mod255(buf, len);
		return 1;
	}
	/* error unknown stuff */
	return 0;
}
