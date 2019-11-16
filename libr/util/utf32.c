/* radare2 - LGPL - Copyright 2017 - kazarmy */

#include <r_types.h>
#include <r_util.h>

/* Convert an UTF-32 buf into a unicode RRune */
R_API int r_utf32_decode(const ut8 *ptr, int ptrlen, RRune *ch, bool bigendian) {
	if (ptrlen < 1) {
		return 0;
	}
	int low = 0;
	int high = 3;
	if (bigendian) {
		low = 3;
		high = 0;
	}
	if (ptrlen > 3) {
		int sign = bigendian ? -1 : 1;
		if (ch) {
			int i;
			*ch = (ut32)ptr[low];
			for (i = 1; i < 4; i++) {
				*ch |= (ut32)ptr[3 - high + i * sign] << 8 * i;
			}
		}
		if (ptr[high] || ptr[high - 1 * sign]) {
			return 4;
		}
		if (ptr[low + 1 * sign]) {
			return 2;
		}
		return 1;
	}
	return 0;
}

/* Convert an UTF-32LE buf into a unicode RRune */
R_API int r_utf32le_decode(const ut8 *ptr, int ptrlen, RRune *ch) {
	return r_utf32_decode (ptr, ptrlen, ch, false);
}

/* Convert an UTF-32BE buf into a unicode RRune */
R_API int r_utf32be_decode(const ut8 *ptr, int ptrlen, RRune *ch) {
	return r_utf32_decode (ptr, ptrlen, ch, true);
}
