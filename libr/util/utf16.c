/* radare2 - LGPL - Copyright 2017 - kazarmy */

#include <r_types.h>
#include <r_util.h>

/* Convert an UTF-16LE buf into a unicode RRune */
R_API int r_utf16le_decode(const ut8 *ptr, int ptrlen, RRune *ch) {
	if (ptrlen < 1) {
		return 0;
	}
	if (ptrlen > 3 && (ptr[1] & 0xdc) == 0xd8 && (ptr[3] & 0xdc) == 0xdc) {
		if (ch) {
			*ch = ((ptr[1] & 3) << 24 | ptr[0] << 16 | (ptr[3] & 3) << 8 | ptr[2]) + 0x10000;
		}
		return 4;
	}
	if (ptrlen > 1 && ptr[1]) {
		if (ch) {
			*ch = ptr[1] << 8 | ptr[0];
		}
		return 2;
	}
	if (ptrlen > 1) {
		if (ch) {
			*ch = (ut32)ptr[0];
		}
		return 1;
	}
	return 0;
}

/* Convert a unicode RRune into a UTF-16LE buf */
R_API int r_utf16le_encode(ut8 *ptr, RRune ch) {
	if (ch < 0x10000) {
		ptr[0] = ch & 0xff;
		ptr[1] = ch >> 8 & 0xff;
		return 2;
	}
	if (ch < 0x110000) {
		RRune high, low;
		ch -= 0x10000;
		high = 0xd800 + (ch >> 10 & 0x3ff);
		low = 0xdc00 + (ch & 0x3ff);
		ptr[0] = high & 0xff;
		ptr[1] = high >> 8 & 0xff;
		ptr[2] = low & 0xff;
		ptr[3] = low >> 8 & 0xff;
		return 4;
	}
	return 0;
}
