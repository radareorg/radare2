/* radare2 - LGPL - Copyright 2017 - kazarmy */

#include <r_types.h>
#include <r_util.h>

/* Convert an UTF-32LE buf into a unicode RRune */
R_API int r_utf32le_decode(const ut8 *ptr, int ptrlen, RRune *ch) {
	if (ptrlen < 1) {
		return 0;
	}
	if (ptrlen > 3) {
		if (ptr[3]) {
			if (ch) {
				*ch = (ut32)ptr[3] << 24 | (ut32)ptr[2] << 16 | (ut32)ptr[1] << 8 | ptr[0];
			}
			return 4;
		}
		if (ptr[2]) {
			if (ch) {
				*ch = (ut32)ptr[2] << 16 | (ut32)ptr[1] << 8 | ptr[0];
			}
			return 4;
		}
		if (ptr[1]) {
			if (ch) {
				*ch = (ut32)ptr[1] << 8 | ptr[0];
			}
			return 2;
		}
		if (ch) {
			*ch = (ut32)ptr[0];
		}
		return 1;
	}
	return 0;
}
