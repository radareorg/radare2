/* radare - LGPL - Copyright 2013 pancake */

#include <r_hash.h>

static const int MOD_ADLER = 65521;

ut32 r_hash_adler32(const ut8 *data, int len) {
	ut32 a = 1, b = 0;
	int index;
	for (index = 0; index < len; ++index) {
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	return (b << 16) | a;
}
