/* radare2 - LGPL - Copyright 2009-2017 pancake */

#include "r_hash.h"

#define SWAP16_TO(x,y) ((x)[1]=(y)&0xff);((x)[0]=((y)>>8)&0xff);
#define SWAP24_TO(x,y) ((x)[2]=(y)&0xff);((x)[1]=((y)>>8)&0xff);((x)[0]=((y)>>16)&0xff);
#define SWAP32_TO(x,y) (x)[3]=(y)&0xff;(x)[2]=((y)>>8)&0xff;(x)[1]=((y)>>16)&0xff;(x)[0]=((y)>>24)&0xff;

/* TODO: do it more beautiful with structs and not spaguetis */
R_API int r_hash_calculate(RHash *ctx, ut64 algobit, const ut8 *buf, int len) {
	if (len < 0) {
		return 0;
	}
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
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC16);
#else
		SWAP16_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC16;
	}
	if (algobit & R_HASH_CRC32) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_32);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC32);
#else
		SWAP32_TO (ctx->digest, res);
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
		return R_HASH_SIZE_HAMDIST;
	}
	if (algobit & R_HASH_PCPRINT) {
		*ctx->digest = r_hash_pcprint (buf, len);
		return R_HASH_SIZE_PCPRINT;
	}
	if (algobit & R_HASH_PARITY) {
		*ctx->digest = r_hash_parity (buf, len);
		return R_HASH_SIZE_PARITY;
	}
	if (algobit & R_HASH_ENTROPY) {
		memset (ctx->digest, 0, R_HASH_SIZE_ENTROPY);
		*ctx->digest = (ut8) r_hash_entropy (buf, len);
		return R_HASH_SIZE_ENTROPY;
	}
	if (algobit & R_HASH_XOR) {
		*ctx->digest = r_hash_xor (buf, len);
		return R_HASH_SIZE_XOR;
	}
	if (algobit & R_HASH_XORPAIR) {
		ut16 res = r_hash_xorpair (buf, len);
		memcpy (ctx->digest, &res, 2);
		return R_HASH_SIZE_XORPAIR;
	}
	if (algobit & R_HASH_MOD255) {
		*ctx->digest = r_hash_mod255 (buf, len);
		return R_HASH_SIZE_MOD255;
	}
	if (algobit & R_HASH_LUHN) {
		*ctx->digest = r_hash_luhn (buf, len);
		return R_HASH_SIZE_LUHN;
	}
	if (algobit & R_HASH_CRC8_SMBUS) {
		ut8 res = r_hash_crc_preset (buf, len, CRC_PRESET_8_SMBUS);
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC8_SMBUS);
		return R_HASH_SIZE_CRC8_SMBUS;
	}
	if (algobit & R_HASH_CRC15_CAN) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_15_CAN);
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC16);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC15_CAN);
#else
		SWAP16_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC15_CAN;
	}
	if (algobit & R_HASH_CRC16_HDLC) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16_HDLC);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC16_HDLC);
#else
		SWAP16_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC16_HDLC;
	}
	if (algobit & R_HASH_CRC16_USB) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16_USB);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC16_USB);
#else
		SWAP16_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC16_USB;
	}
	if (algobit & R_HASH_CRC16_CITT) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16_CITT);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC16_CITT);
#else
		SWAP16_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC16_CITT;
	}
	if (algobit & R_HASH_CRC24) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_24);
//		res <<= 8;
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC24);
#else
		SWAP24_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC24;
	}
	if (algobit & R_HASH_CRC32C) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_32C);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC32C);
#else
		SWAP32_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC32C;
	}
	if (algobit & R_HASH_CRC32_ECMA_267) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_32_ECMA_267);
#if __BYTE_ORDER != __BIG_ENDIAN
		memcpy (ctx->digest, &res, R_HASH_SIZE_CRC32_ECMA_267);
#else
		SWAP32_TO (ctx->digest, res);
#endif
		return R_HASH_SIZE_CRC32_ECMA_267;
	}
	return 0;
}
