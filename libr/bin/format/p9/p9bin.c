/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include "p9bin.h"
#include <r_asm.h>

int r_bin_p9_get_arch(const ut8 *b, int *bits, int *big_endian) {
	unsigned int a = b[0]<<24 | b[1]<<16 | b[2]<<8 | b[3];
	if (bits) *bits = 32;
	if (big_endian) *big_endian = 0;
	switch (a) {
	case I_MAGIC:
		return R_ASM_ARCH_X86;
	case T_MAGIC:
		if (bits) *bits = 64;
		return R_ASM_ARCH_PPC;
	case S_MAGIC:
		if (bits) *bits = 64;
		return R_ASM_ARCH_X86;
	case K_MAGIC:
		return R_ASM_ARCH_SPARC;
	case U_MAGIC:
		if (bits) *bits = 64;
		return R_ASM_ARCH_SPARC;
	case V_MAGIC:
	case M_MAGIC:
	case N_MAGIC:
	case P_MAGIC:
		return R_ASM_ARCH_MIPS;
	case E_MAGIC:
		return R_ASM_ARCH_ARM;
	case Q_MAGIC:
		return R_ASM_ARCH_PPC;
	//case A_MAGIC: // 68020
	}
	return 0;
}
