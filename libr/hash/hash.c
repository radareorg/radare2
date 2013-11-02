/* radare - LGPL - Copyright 2007-2013 pancake */

#include "r_hash.h"
#include "r_util.h"

R_LIB_VERSION(r_hash);

struct { const char *name; ut64 bit; }
static const hash_name_bytes[] = {
	 {"all", UT64_MAX},
	 {"xor", R_HASH_XOR},
	 {"xorpair", R_HASH_XORPAIR},
	 {"md4", R_HASH_MD4},
	 {"md5", R_HASH_MD5},
	 {"sha1", R_HASH_SHA1},
	 {"sha256", R_HASH_SHA256},
	 {"sha384", R_HASH_SHA384},
	 {"sha512", R_HASH_SHA512},
	 {"crc16", R_HASH_CRC16},
	 {"crc32", R_HASH_CRC32},
	 {"adler32", R_HASH_ADLER32},
	 {"xxhash", R_HASH_XXHASH},
	 {"parity", R_HASH_PARITY},
	 {"entropy", R_HASH_ENTROPY},
	 {"hamdist", R_HASH_HAMDIST},
	 {"pcprint", R_HASH_PCPRINT},
	 {"mod255", R_HASH_MOD255},
	 {NULL, 0}
};

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

R_API const char *r_hash_name(ut64 bit) {
    int i;
    for (i=1; hash_name_bytes[i].bit; i++)
        if (bit & hash_name_bytes[i].bit)
            return hash_name_bytes[i].name;
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
	if (bit & R_HASH_ADLER32) return R_HASH_SIZE_ADLER32;
	if (bit & R_HASH_PARITY) return 1;
	if (bit & R_HASH_ENTROPY) return 4; // special case
	if (bit & R_HASH_HAMDIST) return 1;
	if (bit & R_HASH_XOR) return 1;
	if (bit & R_HASH_XORPAIR) return 1;
	if (bit & R_HASH_MOD255) return 1;
	if (bit & R_HASH_PCPRINT) return 1;
	return 0;
}

R_API ut64 r_hash_name_to_bits(const char *name) {
	int i = 0, j, len = 0;
	char name_lowercase[128];
	const char* ptr = name_lowercase;
	ut64 bits = R_HASH_NONE;

	for (j=0;name[j] && j<sizeof (name_lowercase); j++)
		name_lowercase[j] = tolower (name[j]);
	name_lowercase[j] = 0;

	while (name_lowercase[i++]) {
		len++;
		if (name_lowercase[i] == ',') {
			for (j=0; hash_name_bytes[j].name; j++) {
				if (!strncmp (ptr, hash_name_bytes[j].name, len)) {
					bits |= hash_name_bytes[j].bit;
					break;
				}
			}
			ptr = name_lowercase + i + 1;
			len = -1;
		}
		while (name_lowercase[i+1] == ' ') {
			i++;
			ptr++;
		}
	}
	for (i=0; hash_name_bytes[i].name; i++) { //last word of the list
		if (!strcmp (ptr, hash_name_bytes[i].name))
			bits |= hash_name_bytes[i].bit;
	}
	return bits;
}

R_API void r_hash_do_spice(RHash *ctx, int algo, int loops, RHashSeed *seed) {
	ut8 buf[1024];
	int i, len, dlen, hlen = r_hash_size (algo);
	for (i = 0; i< loops; i++) {
		if (seed) {
			if (seed->prefix) {
				memcpy (buf, seed->buf, seed->len);
				memcpy (buf+seed->len, ctx->digest, hlen);
			} else {
				memcpy (buf, ctx->digest, hlen);
				memcpy (buf+hlen, seed->buf, seed->len);
			}
			len = hlen + seed->len;
		} else {
			memcpy (buf, ctx->digest, hlen);
			len = hlen;
		}
		dlen = r_hash_calculate (ctx, algo, buf, len);
	}
}
