/* radare2 - LGPL - Copyright 2009-2017 pancake */

#include "r_hash.h"


#define HANDLE_CRC_PRESET(rbits, aname) \
	do { \
		if (algobit & R_HASH_##aname) { \
			ut##rbits res = r_hash_crc_preset (buf, len, CRC_PRESET_##aname); \
			r_write_be##rbits (ctx->digest, res); \
			return R_HASH_SIZE_##aname; \
		} \
	} while(0)

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
		ctx->entropy = r_hash_entropy (buf, len);
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
#if R_HAVE_CRC8_EXTRA
	HANDLE_CRC_PRESET (8, CRC8_CDMA2000);
	HANDLE_CRC_PRESET (8, CRC8_CDMA2000);
	HANDLE_CRC_PRESET (8, CRC8_DARC);
	HANDLE_CRC_PRESET (8, CRC8_DVB_S2);
	HANDLE_CRC_PRESET (8, CRC8_EBU);
	HANDLE_CRC_PRESET (8, CRC8_ICODE);
	HANDLE_CRC_PRESET (8, CRC8_ITU);
	HANDLE_CRC_PRESET (8, CRC8_MAXIM);
	HANDLE_CRC_PRESET (8, CRC8_ROHC);
	HANDLE_CRC_PRESET (8, CRC8_WCDMA);
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	if (algobit & R_HASH_CRC15_CAN) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_15_CAN);
		r_write_be16 (ctx->digest, res);
		return R_HASH_SIZE_CRC15_CAN;
	}
#endif /* #if R_HAVE_CRC15_EXTRA */

	if (algobit & R_HASH_CRC16) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16);
		r_write_be16 (ctx->digest, res);
		return R_HASH_SIZE_CRC16;
	}
	if (algobit & R_HASH_CRC16_HDLC) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16_HDLC);
		r_write_be16 (ctx->digest, res);
		return R_HASH_SIZE_CRC16_HDLC;
	}
	if (algobit & R_HASH_CRC16_USB) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16_USB);
		r_write_be16 (ctx->digest, res);
		return R_HASH_SIZE_CRC16_USB;
	}
	if (algobit & R_HASH_CRC16_CITT) {
		ut16 res = r_hash_crc_preset (buf, len, CRC_PRESET_16_CITT);
		r_write_be16 (ctx->digest, res);
		return R_HASH_SIZE_CRC16_CITT;
	}
#if R_HAVE_CRC16_EXTRA
	HANDLE_CRC_PRESET (16, CRC16_AUG_CCITT);
	HANDLE_CRC_PRESET (16, CRC16_BUYPASS);
	HANDLE_CRC_PRESET (16, CRC16_CDMA2000);
	HANDLE_CRC_PRESET (16, CRC16_DDS110);
	HANDLE_CRC_PRESET (16, CRC16_DECT_R);
	HANDLE_CRC_PRESET (16, CRC16_DECT_X);
	HANDLE_CRC_PRESET (16, CRC16_DNP);
	HANDLE_CRC_PRESET (16, CRC16_EN13757);
	HANDLE_CRC_PRESET (16, CRC16_GENIBUS);
	HANDLE_CRC_PRESET (16, CRC16_MAXIM);
	HANDLE_CRC_PRESET (16, CRC16_MCRF4XX);
	HANDLE_CRC_PRESET (16, CRC16_RIELLO);
	HANDLE_CRC_PRESET (16, CRC16_T10_DIF);
	HANDLE_CRC_PRESET (16, CRC16_TELEDISK);
	HANDLE_CRC_PRESET (16, CRC16_TMS37157);
	HANDLE_CRC_PRESET (16, CRCA);
	HANDLE_CRC_PRESET (16, CRC16_KERMIT);
	HANDLE_CRC_PRESET (16, CRC16_MODBUS);
	HANDLE_CRC_PRESET (16, CRC16_X25);
	HANDLE_CRC_PRESET (16, CRC16_XMODEM);
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	if (algobit & R_HASH_CRC24) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_24);
		r_write_be24 (ctx->digest, res);
		return R_HASH_SIZE_CRC24;
	}
#endif /* #if R_HAVE_CRC24 */

	if (algobit & R_HASH_CRC32) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_32);
		r_write_be32 (ctx->digest, res);
		return R_HASH_SIZE_CRC32;
	}
	if (algobit & R_HASH_CRC32C) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_32C);
		r_write_be32 (ctx->digest, res);
		return R_HASH_SIZE_CRC32C;
	}
	if (algobit & R_HASH_CRC32_ECMA_267) {
		ut32 res = r_hash_crc_preset (buf, len, CRC_PRESET_32_ECMA_267);
		r_write_be32 (ctx->digest, res);
		return R_HASH_SIZE_CRC32_ECMA_267;
	}
#if R_HAVE_CRC32_EXTRA
	HANDLE_CRC_PRESET (32, CRC32_BZIP2);
	HANDLE_CRC_PRESET (32, CRC32D);
	HANDLE_CRC_PRESET (32, CRC32_MPEG2);
	HANDLE_CRC_PRESET (32, CRC32_POSIX);
	HANDLE_CRC_PRESET (32, CRC32Q);
	HANDLE_CRC_PRESET (32, CRC32_JAMCRC);
	HANDLE_CRC_PRESET (32, CRC32_XFER);
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	HANDLE_CRC_PRESET (64, CRC64);
#endif /* #if R_HAVE_CRC64 */

#if R_HAVE_CRC64_EXTRA
	HANDLE_CRC_PRESET (64, CRC64_ECMA182);
	HANDLE_CRC_PRESET (64, CRC64_WE);
	HANDLE_CRC_PRESET (64, CRC64_XZ);
	HANDLE_CRC_PRESET (64, CRC64_ISO);
#endif /* #if R_HAVE_CRC64_EXTRA */

	return 0;
}
