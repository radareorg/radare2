/* radare - LGPL - Copyright 2009-2013 pancake */

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
R_API int r_hash_calculate(RHash *ctx, ut64 algobit, const ut8 *buf, int len) {
	if (len <= 0)
		return 0;
	if (algobit & R_HASH_MD4) {
		r_hash_do_md4 (ctx, buf, len);
		return R_HASH_SIZE_MD4;
	}
	if (algobit & R_HASH_MD5) {
		r_hash_do_md5 (ctx, buf, len);
		return R_HASH_SIZE_MD5;
	}
	if (algobit & R_HASH_SHA1) {
		r_hash_do_sha1 (ctx, buf, len);
		return R_HASH_SIZE_SHA1;
	}
	if (algobit & R_HASH_SHA256) {
		r_hash_do_sha256 (ctx, buf, len);
		return R_HASH_SIZE_SHA256;
	}
	if (algobit & R_HASH_SHA384) {
		r_hash_do_sha384 (ctx, buf, len);
		return R_HASH_SIZE_SHA384;
	}
	if (algobit & R_HASH_SHA512) {
		r_hash_do_sha512 (ctx, buf, len);
		return R_HASH_SIZE_SHA512;
	}
	if (algobit & R_HASH_CRC16) {
		ut16 res = r_hash_crc16 (0, buf, len);
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC16);
		return R_HASH_SIZE_CRC16;
	}
	if (algobit & R_HASH_CRC32) {
		ut8 *pres;
		ut32 res = r_hash_crc32 (buf, len);
#if CPU_ENDIAN
		/* big endian here */
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC32);
#else
		/* little endian here */
		pres = (ut8 *) &res;
		ctx->digest[0] = pres[3];
		ctx->digest[1] = pres[2];
		ctx->digest[2] = pres[1];
		ctx->digest[3] = pres[0];
#endif
		return R_HASH_SIZE_CRC32;
	}
	if (algobit & R_HASH_XXHASH) {
		ut32 res = r_hash_xxhash (buf, len);
		memcpy (ctx->digest, &res, R_HASH_SIZE_XXHASH);
		return R_HASH_SIZE_XXHASH;
	}
	if (algobit & R_HASH_ADLER32) {
		ut32 res = r_hash_adler32 (buf, len);
		memcpy (ctx->digest, &res, R_HASH_SIZE_ADLER32);
		return R_HASH_SIZE_ADLER32;
	}
	if (algobit & R_HASH_HAMDIST) {
		*ctx->digest = r_hash_hamdist (buf, len);
		return 1;
	}
	if (algobit & R_HASH_PCPRINT) {
		*ctx->digest = r_hash_pcprint (buf, len);
		return 1;
	}
	if (algobit & R_HASH_PARITY) {
		*ctx->digest = r_hash_parity (buf, len);
		return 1;
	}
	if (algobit & R_HASH_ENTROPY) {
		*ctx->digest = (ut8)r_hash_entropy (buf, len);
		return 1;
	}
	if (algobit & R_HASH_XOR) {
		*ctx->digest = r_hash_xor (buf, len);
		return 1;
	}
	if (algobit & R_HASH_XORPAIR) {
		ut16 res = r_hash_xorpair (buf, len);
		memcpy (ctx->digest, &res, 2);
		return 2;
	}
	if (algobit & R_HASH_MOD255) {
		*ctx->digest = r_hash_mod255 (buf, len);
		return 1;
	}
	/* error unknown stuff */
	return 0;
}
