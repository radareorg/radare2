/* radare2 - LGPL - Copyright 2019 pancake */

#include <r_hash.h>

R_API ut8 r_hash_fletcher8(const ut8 *d, size_t length) {
	size_t i;
	ut16 a = 0;
	ut16 b = 0;
	for (i = 0; i < length; i++) {
		a += d[i];
		a = (a & 0xff) + (a >> 8);
		b += a;
		b = (b & 0xff) + (b >> 8);
	}
	return (a & 0xff);
}

R_API ut16 r_hash_fletcher16(const ut8 *data, size_t len) {
	ut32 c0, c1;
	size_t i;

	for (c0 = c1 = 0; len >= 5802; len -= 5802) {
		for (i = 0; i < 5802; i++) {
			c0 = c0 + *data++;
			c1 = c1 + c0;
		}
		c0 %= 0xff;
		c1 %= 0xff;
	}
	for (i = 0; i < len; i++) {
		c0 += *data++;
		c1 += c0;
	}
	c0 %= 0xff;
	c1 %= 0xff;
	return (c1 << 8 | c0);
}

R_API ut32 r_hash_fletcher32(const ut8 *data, size_t len) {
	ut32 c0, c1;
	size_t i;
	ut8 word[sizeof (ut16)];
	for (c0 = c1 = 0; len >= 360; len -= 360) {
		for (i = 0; i < 360; i+=2) {
			size_t left = 360 - i;
			memset (word, 0, sizeof (word));
			memcpy (word, data, R_MIN (sizeof (word), left));
			c0 += r_read_le16 (word);
			c1 += c0;
			data += 2;
		}
		c0 %= UT16_MAX;
		c1 %= UT16_MAX;
	}
	for (i = 0; i < len; i+=2) {
		size_t left = len - i;
		memset (word, 0, sizeof (word));
		memcpy (word, data, R_MIN (sizeof (word), left));
		c0 += r_read_le16 (word);
		c1 += c0;
		data += 2;
	}
	c0 %= UT16_MAX;
	c1 %= UT16_MAX;
	return (c1 << 16 | c0);
}

R_API ut64 r_hash_fletcher64(const ut8 *addr, size_t len) {
	const ut8 *p32 = addr;
	const ut8 *p32end = addr + len;
	ut32 lo32 = 0;
	ut32 hi32 = 0;

	ut8 word[sizeof (ut32)];
	while (p32 < p32end) {
		size_t left = p32end - p32;
		memset (word, 0, sizeof (word));
		memcpy (word, p32, R_MIN (sizeof (word), left));
		ut32 w = r_read_le32 (word);
		lo32 += w;
		p32 += sizeof (ut32);
		hi32 += lo32;
	}
	return ((ut64)hi32 << 32) | lo32;
}
