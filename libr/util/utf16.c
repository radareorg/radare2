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
