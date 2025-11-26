/* radare2 - LGPL - MIPS helpers */

#ifndef R_MIPS_H
#define R_MIPS_H

#include <r_types.h>

static inline ut64 r_mips_align_gp(ut64 gp) {
	return gp == UT64_MAX? gp: (gp + 0xf) & ~(ut64)0xf;
}

#endif
