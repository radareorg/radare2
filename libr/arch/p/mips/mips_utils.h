/* radare2 - LGPL - Copyright */

#ifndef R_MIPS_UTILS_H
#define R_MIPS_UTILS_H

#include <r_endian.h>
#include <r_bin.h>

static inline ut64 mips_read_ptr_at(RBin *bin, ut64 addr, bool be, int bits) {
	const int ptrsz = bits == 64 ? 8 : 4;
	ut8 v[8] = {0};
	if (!bin || !bin->iob.read_at (bin->iob.io, addr, v, ptrsz)) {
		return UT64_MAX;
	}
	return ptrsz == 8 ? r_read_ble64 (v, be) : r_read_ble32 (v, be);
}

#endif
