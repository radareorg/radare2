/* radare - LGPL - Copyright 2011-2021 pancake<nopcode.org>, keegan */

#include "p9bin.h"
#include <r_asm.h>

bool r_bin_p9_get_arch(RBuffer *b, RSysArch *arch, int *bits, int *big_endian) {
	ut32 header = r_buf_read_be32_at (b, 0);
	if (header == UT32_MAX) {
		return false;
	}

	*bits = 32;
	*big_endian = 0;

	switch (header) {
	case MAGIC_68020:
		*big_endian = 1;
		*arch = R_SYS_ARCH_M68K;
		return true;

	case MAGIC_AMD64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_INTEL_386:
		*arch = R_SYS_ARCH_X86;
		return true;

	case MAGIC_SPARC64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_SPARC:
		*big_endian = 1;
		*arch = R_SYS_ARCH_SPARC;
		return true;

	case MAGIC_MIPS_4000BE:
		*big_endian = 1;
		/* fallthrough */
	case MAGIC_MIPS_4000LE:
		*bits = 64;
		*arch = R_SYS_ARCH_MIPS;
		return true;

	case MAGIC_MIPS_3000BE:
		*big_endian = 1;
		/* fallthrough */
	case MAGIC_MIPS_3000LE:
		*arch = R_SYS_ARCH_MIPS;
		return true;

	case MAGIC_ARM64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_ARM:
		*arch = R_SYS_ARCH_ARM;
		return true;

	case MAGIC_PPC64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_PPC:
		*big_endian = 1;
		*arch = R_SYS_ARCH_PPC;
		return true;
	}

	return false;
}
