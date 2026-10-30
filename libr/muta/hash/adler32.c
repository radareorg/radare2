/* radare - LGPL - Copyright 2013-2016 pancake */

#include <r_hash.h>

R_API ut32 r_hash_adler32(const ut8 *data, int len) {
	static const int MOD_ADLER = 65521;
	// zlib's NMAX: the longest run whose sums fit in ut32 before a modulo
	static const int NMAX = 5552;
	ut32 a = 1, b = 0;
	int index;
	for (index = 0; index < len;) {
		int end = index + R_MIN (len - index, NMAX);
		for (; index < end; index++) {
			a += data[index];
			b += a;
		}
		a %= MOD_ADLER;
		b %= MOD_ADLER;
	}
	return (b << 16) | a;
}
