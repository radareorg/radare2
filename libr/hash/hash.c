/* radare - LGPL - Copyright 2007-2017 pancake */

#include <r_hash.h>
#include "r_util.h"
#ifdef _MSC_VER
#define strcasecmp stricmp
#endif
R_LIB_VERSION (r_hash);

struct {
	const char *name; ut64 bit;
}
static const hash_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "xor", R_HASH_XOR },
	{ "xorpair", R_HASH_XORPAIR },
	{ "md4", R_HASH_MD4 },
	{ "md5", R_HASH_MD5 },
	{ "sha1", R_HASH_SHA1 },
	{ "sha256", R_HASH_SHA256 },
	{ "sha384", R_HASH_SHA384 },
	{ "sha512", R_HASH_SHA512 },
	{ "adler32", R_HASH_ADLER32 },
	{ "xxhash", R_HASH_XXHASH },
	{ "parity", R_HASH_PARITY },
	{ "entropy", R_HASH_ENTROPY },
	{ "hamdist", R_HASH_HAMDIST },
	{ "pcprint", R_HASH_PCPRINT },
	{ "mod255", R_HASH_MOD255 },
	// {"base64", R_HASH_BASE64},
	// {"base91", R_HASH_BASE91},
	// {"punycode", R_HASH_PUNYCODE},
	{ "luhn", R_HASH_LUHN },

	{ "crc8smbus", R_HASH_CRC8_SMBUS },
#if R_HAVE_CRC8_EXTRA
	{ /* CRC-8/CDMA2000     */ "crc8cdma2000", R_HASH_CRC8_CDMA2000 },
	{ /* CRC-8/DARC         */ "crc8darc", R_HASH_CRC8_DARC },
	{ /* CRC-8/DVB-S2       */ "crc8dvbs2", R_HASH_CRC8_DVB_S2 },
	{ /* CRC-8/EBU          */ "crc8ebu", R_HASH_CRC8_EBU },
	{ /* CRC-8/I-CODE       */ "crc8icode", R_HASH_CRC8_ICODE },
	{ /* CRC-8/ITU          */ "crc8itu", R_HASH_CRC8_ITU },
	{ /* CRC-8/MAXIM        */ "crc8maxim", R_HASH_CRC8_MAXIM },
	{ /* CRC-8/ROHC         */ "crc8rohc", R_HASH_CRC8_ROHC },
	{ /* CRC-8/WCDMA        */ "crc8wcdma", R_HASH_CRC8_WCDMA },
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	{ "crc15can", R_HASH_CRC15_CAN },
#endif /* #if R_HAVE_CRC15_EXTRA */

	{ "crc16", R_HASH_CRC16 },
	{ "crc16hdlc", R_HASH_CRC16_HDLC },
	{ /* CRC-16/USB         */ "crc16usb", R_HASH_CRC16_USB },
	{ /* CRC-16/CCITT-FALSE */ "crc16citt", R_HASH_CRC16_CITT },
#if R_HAVE_CRC16_EXTRA
	{ /* CRC-16/AUG-CCITT   */ "crc16augccitt", R_HASH_CRC16_AUG_CCITT },
	{ /* CRC-16/BUYPASS     */ "crc16buypass", R_HASH_CRC16_BUYPASS },
	{ /* CRC-16/CDMA2000    */ "crc16cdma2000", R_HASH_CRC16_CDMA2000 },
	{ /* CRC-16/DDS-110     */ "crc16dds110", R_HASH_CRC16_DDS110 },
	{ /* CRC-16/RECT-R      */ "crc16dectr", R_HASH_CRC16_DECT_R },
	{ /* CRC-16/RECT-X      */ "crc16dectx", R_HASH_CRC16_DECT_X },
	{ /* CRC-16/DNP         */ "crc16dnp", R_HASH_CRC16_DNP },
	{ /* CRC-16/EN-13757    */ "crc16en13757", R_HASH_CRC16_EN13757 },
	{ /* CRC-16/GENIBUS     */ "crc16genibus", R_HASH_CRC16_GENIBUS },
	{ /* CRC-16/MAXIM       */ "crc16maxim", R_HASH_CRC16_MAXIM },
	{ /* CRC-16/MCRF4XX     */ "crc16mcrf4xx", R_HASH_CRC16_MCRF4XX },
	{ /* CRC-16/RIELLO      */ "crc16riello", R_HASH_CRC16_RIELLO },
	{ /* CRC-16/T10-DIF     */ "crc16t10dif", R_HASH_CRC16_T10_DIF },
	{ /* CRC-16/TELEDISK    */ "crc16teledisk", R_HASH_CRC16_TELEDISK },
	{ /* CRC-16/TMS37157    */ "crc16tms37157", R_HASH_CRC16_TMS37157 },
	{ /* CRC-A              */ "crca", R_HASH_CRCA },
	{ /* CRC-16/KERMIT      */ "crc16kermit", R_HASH_CRC16_KERMIT },
	{ /* CRC-16/MODBUS      */ "crc16modbus", R_HASH_CRC16_MODBUS },
	{ /* CRC-16/X-25        */ "crc16x25", R_HASH_CRC16_X25 },
	{ /* CRC-16/XMODEM      */ "crc16xmodem", R_HASH_CRC16_XMODEM },
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	{ "crc24", R_HASH_CRC24 },
#endif /* #if R_HAVE_CRC24 */

	{ "crc32", R_HASH_CRC32 },
	{ "crc32c", R_HASH_CRC32C },
	{ "crc32ecma267", R_HASH_CRC32_ECMA_267 },
#if R_HAVE_CRC32_EXTRA
	{ /* CRC-32/BZIP2       */ "crc32bzip2", R_HASH_CRC32_BZIP2 },
	{ /* CRC-32D            */ "crc32d", R_HASH_CRC32D },
	{ /* CRC-32/MPEG2       */ "crc32mpeg2", R_HASH_CRC32_MPEG2 },
	{ /* CRC-32/POSIX       */ "crc32posix", R_HASH_CRC32_POSIX },
	{ /* CRC-32Q            */ "crc32q", R_HASH_CRC32Q },
	{ /* CRC-32/JAMCRC      */ "crc32jamcrc", R_HASH_CRC32_JAMCRC },
	{ /* CRC-32/XFER        */ "crc32xfer",   R_HASH_CRC32_XFER },
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	{ /* CRC-64             */ "crc64", R_HASH_CRC64 },
#endif /* #if R_HAVE_CRC64 */

#if R_HAVE_CRC64_EXTRA
	{ /* CRC-64/ECMA-182    */ "crc64ecma", R_HASH_CRC64_ECMA182 },
	{ /* CRC-64/WE          */ "crc64we", R_HASH_CRC64_WE },
	{ /* CRC-64/XZ          */ "crc64xz", R_HASH_CRC64_XZ },
	{ /* CRC-64/ISO         */ "crc64iso", R_HASH_CRC64_ISO },
#endif /* #if R_HAVE_CRC64_EXTRA */
	{ NULL, 0 }
};

/* returns 0-100 */
R_API int r_hash_pcprint(const ut8 *buffer, ut64 len) {
	const ut8 *end = buffer + len;
	int n;
	if (len < 1) {
		return 0;
	}
	for (n = 0; buffer < end; buffer++) {
		if (IS_PRINTABLE (*buffer)) {
			n++;
		}
	}
	return ((100 * n) / len);
}

R_API int r_hash_parity(const ut8 *buf, ut64 len) {
	const ut8 *end = buf + len;
	ut32 ones = 0;
	for (; buf < end; buf++) {
		ut8 x = buf[0];
		ones += ((x & 128)? 1: 0) + ((x & 64)? 1: 0) + ((x & 32)? 1: 0) + ((x & 16)? 1: 0) +
		((x & 8)? 1: 0) + ((x & 4)? 1: 0) + ((x & 2)? 1: 0) + ((x & 1)? 1: 0);
	}
	return ones % 2;
}

/* These functions comes from 0xFFFF */
/* fmi: nopcode.org/0xFFFF */
R_API ut16 r_hash_xorpair(const ut8 *a, ut64 len) {
	ut16 result = 0, *b = (ut16 *) a;
	for (len >>= 1; len--; b++) {
		result ^= *b;
	}
	return result;
}

R_API ut8 r_hash_xor(const ut8 *b, ut64 len) {
	ut8 res = 0;
	for (; len--; b++) {
		res ^= *b;
	}
	return res;
}

R_API ut8 r_hash_mod255(const ut8 *b, ut64 len) {
	int i, c = 0;
	/* from gdb */
	for (i = 0; i < len; i++) {
		c += b[i];
	}
	return c % 255;
}

R_API ut8 r_hash_deviation(const ut8 *b, ut64 len) {
	int i, c;
	for (c = i = 0, len--; i < len; i++) {
		c += R_ABS (b[i + 1] - b[i]);
	}
	return c;
}

R_API const char *r_hash_name(ut64 bit) {
	int i;
	for (i = 1; hash_name_bytes[i].bit; i++) {
		if (bit & hash_name_bytes[i].bit) {
			return hash_name_bytes[i].name;
		}
	}
	return "";
}

R_API int r_hash_size(ut64 algo) {
#	define ALGOBIT(x) if (algo & R_HASH_ ## x) { return R_HASH_SIZE_ ## x; }
	ALGOBIT (MD4);
	ALGOBIT (MD5);
	ALGOBIT (SHA1);
	ALGOBIT (SHA256);
	ALGOBIT (SHA384);
	ALGOBIT (SHA512);
	ALGOBIT (XXHASH);
	ALGOBIT (ADLER32);
	ALGOBIT (PARITY);
	ALGOBIT (ENTROPY);
	ALGOBIT (HAMDIST);
	ALGOBIT (XOR);
	ALGOBIT (XORPAIR);
	ALGOBIT (MOD255);
	ALGOBIT (PCPRINT);
	ALGOBIT (LUHN);

	ALGOBIT (CRC8_SMBUS);
#if R_HAVE_CRC8_EXTRA
	ALGOBIT (CRC8_CDMA2000);
	ALGOBIT (CRC8_DARC);
	ALGOBIT (CRC8_DVB_S2);
	ALGOBIT (CRC8_EBU);
	ALGOBIT (CRC8_ICODE);
	ALGOBIT (CRC8_ITU);
	ALGOBIT (CRC8_MAXIM);
	ALGOBIT (CRC8_ROHC);
	ALGOBIT (CRC8_WCDMA);
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	ALGOBIT (CRC15_CAN);
#endif /* #if R_HAVE_CRC15_EXTRA */

	ALGOBIT (CRC16);
	ALGOBIT (CRC16_HDLC);
	ALGOBIT (CRC16_USB);
	ALGOBIT (CRC16_CITT);
#if R_HAVE_CRC16_EXTRA
	ALGOBIT (CRC16_AUG_CCITT);
	ALGOBIT (CRC16_BUYPASS)
	ALGOBIT (CRC16_CDMA2000);
	ALGOBIT (CRC16_DDS110);
	ALGOBIT (CRC16_DECT_R);
	ALGOBIT (CRC16_DECT_X);
	ALGOBIT (CRC16_DNP);
	ALGOBIT (CRC16_EN13757);
	ALGOBIT (CRC16_GENIBUS);
	ALGOBIT (CRC16_MAXIM);
	ALGOBIT (CRC16_MCRF4XX);
	ALGOBIT (CRC16_RIELLO);
	ALGOBIT (CRC16_T10_DIF);
	ALGOBIT (CRC16_TELEDISK);
	ALGOBIT (CRC16_TMS37157);
	ALGOBIT (CRCA);
	ALGOBIT (CRC16_KERMIT);
	ALGOBIT (CRC16_MODBUS);
	ALGOBIT (CRC16_X25);
	ALGOBIT (CRC16_XMODEM);
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	ALGOBIT (CRC24);
#endif /* #if R_HAVE_CRC24 */

	ALGOBIT (CRC32);
	ALGOBIT (CRC32C);
	ALGOBIT (CRC32_ECMA_267);
#if R_HAVE_CRC32_EXTRA
	ALGOBIT (CRC32_BZIP2);
	ALGOBIT (CRC32D);
	ALGOBIT (CRC32_MPEG2);
	ALGOBIT (CRC32_POSIX);
	ALGOBIT (CRC32Q);
	ALGOBIT (CRC32_JAMCRC);
	ALGOBIT (CRC32_XFER);
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	ALGOBIT (CRC64);
#endif /* #if R_HAVE_CRC64 */

#if R_HAVE_CRC64_EXTRA
	ALGOBIT (CRC64_ECMA182);
	ALGOBIT (CRC64_WE);
	ALGOBIT (CRC64_XZ);
	ALGOBIT (CRC64_ISO);
#endif /* #if R_HAVE_CRC64_EXTRA */
	return 0;
}

/* Converts a comma separated list of names to the respective bit combination */
R_API ut64 r_hash_name_to_bits(const char *name) {
	char tmp[128];
	int i;
	const char *ptr;
	ut64 ret;

	ret = 0;
	ptr = name;

	if (!ptr) {
		return ret;
	}

	do {
		/* Eat everything up to the comma */
		for (i = 0; *ptr && *ptr != ',' && i < sizeof (tmp) - 1; i++) {
			tmp[i] = *ptr++;
		}

		/* Safety net */
		tmp[i] = '\0';

		for (i = 0; hash_name_bytes[i].name; i++) {
			if (!strcasecmp (tmp, hash_name_bytes[i].name)) {
				ret |= hash_name_bytes[i].bit;
				break;
			}
		}

		/* Skip the trailing comma, if any */
		if (*ptr) {
			ptr++;
		}
	} while (*ptr);

	return ret;
}

R_API void r_hash_do_spice(RHash *ctx, ut64 algo, int loops, RHashSeed *seed) {
	ut8 buf[1024];
	int i, len, hlen = r_hash_size (algo);
	for (i = 0; i < loops; i++) {
		if (seed) {
			if (seed->prefix) {
				memcpy (buf, seed->buf, seed->len);
				memcpy (buf + seed->len, ctx->digest, hlen);
			} else {
				memcpy (buf, ctx->digest, hlen);
				memcpy (buf + hlen, seed->buf, seed->len);
			}
			len = hlen + seed->len;
		} else {
			memcpy (buf, ctx->digest, hlen);
			len = hlen;
		}
		(void) r_hash_calculate (ctx, algo, buf, len);
	}
}

R_API char *r_hash_to_string(RHash *ctx, const char *name, const ut8 *data, int len) {
	ut64 algo = r_hash_name_to_bits (name);
	char *digest_hex = NULL;
	RHash *myctx = NULL;
	int i, digest_size;
	if (!algo || !data) {
		return NULL;
	}
	if (!ctx) {
		myctx = ctx = r_hash_new (true, algo);
	}
	r_hash_do_begin (ctx, algo);
	digest_size = r_hash_calculate (ctx, algo, data, len);
	r_hash_do_end (ctx, algo);
	if (digest_size == 0) {
		digest_hex = calloc (16, 1);
		snprintf (digest_hex, 15, "%02.8f", ctx->entropy);
	} else if (digest_size > 0) {
		if (digest_size * 2 < digest_size) {
			digest_hex = NULL;
		} else {
			digest_hex = malloc ((digest_size * 2) + 1);
			for (i = 0; i < digest_size; i++) {
				sprintf (digest_hex + (i * 2), "%02x", ctx->digest[i]);
			}
			digest_hex[digest_size * 2] = 0;
		}
	}
	r_hash_free (myctx);
	return digest_hex;
}
