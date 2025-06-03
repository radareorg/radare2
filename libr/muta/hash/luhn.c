/* radare2 - LGPL - 2016-2018 - Copyright (C) moritz */

#include <r_hash.h>

R_API ut64 r_hash_luhn(const ut8 *buf, ut64 len) {
	int curDigit, parity = (len - 1) % 2;
	ut64 i, sum = 0;
	char curChar[2] = {0, 0};
	for (i = len; i > 0; i--) {
		curChar[0] = buf[i - 1];
		// ??? atoi here wtf
		curDigit = atoi (curChar);
		if (parity == i % 2) {
			curDigit *= 2;
		}
		sum += curDigit / 10;
		sum += curDigit % 10;
	}
	return sum % 10;
}
