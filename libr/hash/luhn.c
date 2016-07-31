/* Copyright (C) radare2 - 2007-2016 - pancake */

#include <r_types.h>
#include <r_util.h>

R_API ut64 r_hash_luhn(const ut8 *buf, ut64 len) {
	ut64 sum = 0;
	int parity = (len-1) % 2;
	char curChar[2] = "\0"; 
	for (int i = len; i > 0 ; i--) {
		curChar[0] = buf[i-1];
		int curDigit = atoi(curChar);

		if (parity == i % 2) {
			curDigit = curDigit * 2;
		}

		sum += curDigit / 10;
		sum += curDigit % 10;
	}
	return sum % 10;
}
