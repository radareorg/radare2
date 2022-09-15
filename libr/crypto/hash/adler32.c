/* radare - LGPL - Copyright 2013-2016 pancake */

#include <r_hash.h>

R_API ut32 r_hash_adler32(const ut8 *data, int len) {
	static const int MOD_ADLER = 65521;
	ut32 a = 1, b = 0;
	int index;
	for (index = 0; index < len; index++) {
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	return (b << 16) | a;
}
