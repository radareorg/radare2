/* radare - LGPL - Copyright 2007-2013 pancake */

#include "r_hash.h"

/* returns 0-100 */
R_API int r_hash_pcprint(const ut8 *buffer, ut64 len) {
	const ut8 *end = buffer + len;
	int n;
	for (n=0; buffer<end; buffer++)
		if (IS_PRINTABLE (*buffer))
			n++;
	return ((100*n)/len);
}

R_API int r_hash_parity(const ut8 *buf, ut64 len) {
	const ut8 *end = buf+len;
	ut32 ones = 0;
	for (;buf<end;buf++) {
		ut8 x = buf[0];
		ones += ((x&128)?1:0) + ((x&64)?1:0) + ((x&32)?1:0) + ((x&16)?1:0) +
			((x&8)?1:0) + ((x&4)?1:0) + ((x&2)?1:0) + ((x&1)?1:0);
	}
	return ones%2;
}

/* These functions comes from 0xFFFF */
/* fmi: nopcode.org/0xFFFF */
R_API ut16 r_hash_xorpair(const ut8 *a, ut64 len) {
	ut16 result = 0, *b = (ut16 *)a;
	for (len>>=1; len--; b++)
		result ^= *b;
	return result;
}

R_API ut8 r_hash_xor(const ut8 *b, ut64 len) {
	ut8 res = 0;
	for (; len--; b++)
		res ^= *b;
	return res;
}

R_API ut8 r_hash_mod255(const ut8 *b, ut64 len) {
	int i, c = 0;
	/* from gdb */
	for (i = 0; i < len; i++)
		c += b[i];
	return c%255;
}

R_API ut8 r_hash_deviation(const ut8 *b, ut64 len) {
	int i, c;
	for (c = i = 0, --len; i < len; i++)
		c += R_ABS (b[i+1] - b[i]);
	return c;
}

/* TODO: rewrite in a non-spaguetty way */
R_API const char *r_hash_name(ut64 bit) {
	if (bit & R_HASH_MD4) return "md4";
	if (bit & R_HASH_MD5) return "md5";
	if (bit & R_HASH_SHA1) return "sha1";
	if (bit & R_HASH_SHA256) return "sha256";
	if (bit & R_HASH_SHA384) return "sha384";
	if (bit & R_HASH_SHA512) return "sha512";
	if (bit & R_HASH_CRC16) return "crc16";
	if (bit & R_HASH_CRC32) return "crc32";
	if (bit & R_HASH_PARITY) return "parity";
	if (bit & R_HASH_ENTROPY) return "entropy";
	if (bit & R_HASH_HAMDIST) return "hamdist";
	if (bit & R_HASH_XOR) return "xor";
	if (bit & R_HASH_XORPAIR) return "xorpair";
	if (bit & R_HASH_MOD255) return "mod255";
	if (bit & R_HASH_PCPRINT) return "pcprint";
	if (bit & R_HASH_XXHASH) return "xxhash";
	return "";
}

R_API int r_hash_size(int bit) {
	if (bit & R_HASH_MD4) return R_HASH_SIZE_MD4;
	if (bit & R_HASH_MD5) return R_HASH_SIZE_MD5;
	if (bit & R_HASH_SHA1) return R_HASH_SIZE_SHA1;
	if (bit & R_HASH_SHA256) return R_HASH_SIZE_SHA256;
	if (bit & R_HASH_SHA384) return R_HASH_SIZE_SHA384;
	if (bit & R_HASH_SHA512) return R_HASH_SIZE_SHA512;
	if (bit & R_HASH_CRC16) return R_HASH_SIZE_CRC16;
	if (bit & R_HASH_CRC32) return R_HASH_SIZE_CRC32;
	if (bit & R_HASH_XXHASH) return R_HASH_SIZE_XXHASH;
	if (bit & R_HASH_PARITY) return 1;
	if (bit & R_HASH_ENTROPY) return 4; // special case
	if (bit & R_HASH_HAMDIST) return 1;
	if (bit & R_HASH_XOR) return 1;
	if (bit & R_HASH_XORPAIR) return 1;
	if (bit & R_HASH_MOD255) return 1;
	if (bit & R_HASH_PCPRINT) return 1;
	return 0;
}
/* TODO: ignore case.. we have to use strcasestr */
R_API ut64 r_hash_name_to_bits(const char *name) {
	ut64 bits = R_HASH_NONE;
	if (strstr (name, "all")) return UT64_MAX;
	if (strstr (name, "md4")) bits |= R_HASH_MD4;
	if (strstr (name, "md5")) bits |= R_HASH_MD5;
	if (strstr (name, "sha1")) bits |= R_HASH_SHA1;
	if (strstr (name, "sha256")) bits |= R_HASH_SHA256;
	if (strstr (name, "sha384")) bits |= R_HASH_SHA384;
	if (strstr (name, "sha512")) bits |= R_HASH_SHA512;
	if (strstr (name, "crc16")) bits |= R_HASH_CRC16;
	if (strstr (name, "crc32")) bits |= R_HASH_CRC32;
	if (strstr (name, "xxhash")) bits |= R_HASH_XXHASH;
	if (strstr (name, "xorpair")) bits |= R_HASH_XORPAIR;
	else if (strstr (name, "xor")) bits |= R_HASH_XOR;
	if (strstr (name, "parity")) bits |= R_HASH_PARITY;
	if (strstr (name, "entropy")) bits |= R_HASH_ENTROPY;
	if (strstr (name, "hamdist")) bits |= R_HASH_HAMDIST;
	if (strstr (name, "pcprint")) bits |= R_HASH_PCPRINT;
	if (strstr (name, "mod255")) bits |= R_HASH_MOD255;
	return bits;
}
