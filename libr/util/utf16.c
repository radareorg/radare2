/* radare2 - LGPL - Copyright 2017 - kazarmy */

#include <r_types.h>
#include <r_util.h>

/* Convert an UTF-16 buf into a unicode RRune */
R_API int r_utf16_decode(const ut8 *ptr, int ptrlen, RRune *ch, bool bigendian) {
	if (ptrlen < 1) {
		return 0;
	}
	int high = !bigendian;
	int low = !high;
	if (ptrlen > 3 && (ptr[high] & 0xdc) == 0xd8 && (ptr[high + 2] & 0xdc) == 0xdc) {
		if (ch) {
			*ch = ((ptr[high] & 3) << 24 | ptr[low] << 16 | (ptr[high + 2] & 3) << 8 | ptr[low + 2])
			      + 0x10000;
		}
		return 4;
	}
	if (ptrlen > 1 && ptr[high]) {
		if (ch) {
			*ch = ptr[high] << 8 | ptr[low];
		}
		return 2;
	}
	if (ptrlen > 1) {
		if (ch) {
			*ch = (ut32)ptr[low];
		}
		return 1;
	}
	return 0;
}

/* Convert an UTF-16LE buf into a unicode RRune */
R_API int r_utf16le_decode(const ut8 *ptr, int ptrlen, RRune *ch) {
	return r_utf16_decode (ptr, ptrlen, ch, false);
}

/* Convert an UTF-16BE buf into a unicode RRune */
R_API int r_utf16be_decode(const ut8 *ptr, int ptrlen, RRune *ch) {
	return r_utf16_decode (ptr, ptrlen, ch, true);
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
