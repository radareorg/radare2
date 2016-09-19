/* Copyright (C) radare2 - 2016 - moritz */

#include <r_types.h>
#include <r_util.h>

R_API ut64 r_hash_luhn(const ut8 *buf, ut64 len) {
	int i, curDigit, parity = (len - 1) % 2;
	ut64 sum = 0;
	char curChar[2] = "\0"; 

	for (i = len; i > 0 ; i--) {
		curChar[0] = buf[i - 1];
		curDigit = atoi (curChar);
		if (parity == i % 2) {
			curDigit *= 2;
		}
		sum += curDigit / 10;
		sum += curDigit % 10;
	}
	return sum % 10;
}
