#include "uuid_hash.h"
#include <string.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ------------------------------ SHA-1 ------------------------------ */

static void sha1_block(ut32 h[5], const ut8 *p) {
	ut32 w[80];
	int i;
	for (i = 0; i < 16; i++) {
		w[i] = ((ut32)p[4 * i] << 24) | ((ut32)p[4 * i + 1] << 16)
			| ((ut32)p[4 * i + 2] << 8) | (ut32)p[4 * i + 3];
	}
	for (i = 16; i < 80; i++) {
		w[i] = ROL32 (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}
	ut32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
	for (i = 0; i < 80; i++) {
		ut32 f, k;
		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999u;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1u;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDCu;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6u;
		}
		ut32 t = ROL32 (a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = ROL32 (b, 30);
		b = a;
		a = t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

void r_uuid_sha1_init(RUuidSha1 *c) {
	c->h[0] = 0x67452301u;
	c->h[1] = 0xEFCDAB89u;
	c->h[2] = 0x98BADCFEu;
	c->h[3] = 0x10325476u;
	c->h[4] = 0xC3D2E1F0u;
	c->total = 0;
	c->n = 0;
}

void r_uuid_sha1_update(RUuidSha1 *c, const ut8 *p, size_t len) {
	c->total += len;
	while (len) {
		size_t take = 64 - c->n;
		if (take > len) {
			take = len;
		}
		memcpy (c->buf + c->n, p, take);
		c->n += take;
		p += take;
		len -= take;
		if (c->n == 64) {
			sha1_block (c->h, c->buf);
			c->n = 0;
		}
	}
}

void r_uuid_sha1_final(RUuidSha1 *c, ut8 out[20]) {
	static const ut8 one = 0x80;
	static const ut8 zero = 0;
	ut64 bits = c->total << 3;
	ut8 lb[8];
	int i;

	r_uuid_sha1_update (c, &one, 1);
	while (c->n != 56) {
		r_uuid_sha1_update (c, &zero, 1);
	}
	for (i = 0; i < 8; i++) {
		lb[i] = (ut8)(bits >> (56 - 8 * i));
	}
	r_uuid_sha1_update (c, lb, 8);
	for (i = 0; i < 5; i++) {
		out[4 * i] = (ut8)(c->h[i] >> 24);
		out[4 * i + 1] = (ut8)(c->h[i] >> 16);
		out[4 * i + 2] = (ut8)(c->h[i] >> 8);
		out[4 * i + 3] = (ut8)(c->h[i]);
	}
}

/* ------------------------------ MD5 ------------------------------ */

static const ut32 md5_k[64] = {
	0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
	0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
	0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
	0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
	0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
	0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
	0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
	0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
	0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
	0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
	0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
	0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
	0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
	0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
	0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
	0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

static const ut8 md5_s[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static void md5_block(ut32 h[4], const ut8 *p) {
	ut32 m[16];
	int i;
	for (i = 0; i < 16; i++) {
		m[i] = (ut32)p[4 * i] | ((ut32)p[4 * i + 1] << 8)
			| ((ut32)p[4 * i + 2] << 16) | ((ut32)p[4 * i + 3] << 24);
	}
	ut32 a = h[0], b = h[1], c = h[2], d = h[3];
	for (i = 0; i < 64; i++) {
		ut32 f;
		int g;
		if (i < 16) {
			f = (b & c) | (~b & d);
			g = i;
		} else if (i < 32) {
			f = (d & b) | (~d & c);
			g = (5 * i + 1) % 16;
		} else if (i < 48) {
			f = b ^ c ^ d;
			g = (3 * i + 5) % 16;
		} else {
			f = c ^ (b | ~d);
			g = (7 * i) % 16;
		}
		f = f + a + md5_k[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + ROL32 (f, md5_s[i]);
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
}

void r_uuid_md5_init(RUuidMd5 *c) {
	c->h[0] = 0x67452301u;
	c->h[1] = 0xefcdab89u;
	c->h[2] = 0x98badcfeu;
	c->h[3] = 0x10325476u;
	c->total = 0;
	c->n = 0;
}

void r_uuid_md5_update(RUuidMd5 *c, const ut8 *p, size_t len) {
	c->total += len;
	while (len) {
		size_t take = 64 - c->n;
		if (take > len) {
			take = len;
		}
		memcpy (c->buf + c->n, p, take);
		c->n += take;
		p += take;
		len -= take;
		if (c->n == 64) {
			md5_block (c->h, c->buf);
			c->n = 0;
		}
	}
}

void r_uuid_md5_final(RUuidMd5 *c, ut8 out[16]) {
	static const ut8 one = 0x80;
	static const ut8 zero = 0;
	ut64 bits = c->total << 3;
	ut8 lb[8];
	int i;

	r_uuid_md5_update (c, &one, 1);
	while (c->n != 56) {
		r_uuid_md5_update (c, &zero, 1);
	}
	for (i = 0; i < 8; i++) {
		lb[i] = (ut8)(bits >> (8 * i));
	}
	r_uuid_md5_update (c, lb, 8);
	for (i = 0; i < 4; i++) {
		out[4 * i] = (ut8)(c->h[i]);
		out[4 * i + 1] = (ut8)(c->h[i] >> 8);
		out[4 * i + 2] = (ut8)(c->h[i] >> 16);
		out[4 * i + 3] = (ut8)(c->h[i] >> 24);
	}
}
