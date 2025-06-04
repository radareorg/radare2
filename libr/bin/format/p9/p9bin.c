/* radare2 - MIT - Copyright 2021-2022 - pancake, keegan, Plan 9 Foundation */

#include "p9bin.h"
#include <r_asm.h>

bool r_bin_p9_get_arch(RBuffer *b, const char **arch, int *bits, int *big_endian) {
	ut32 header = r_buf_read_be32_at (b, 0);
	if (header == UT32_MAX) {
		return false;
	}

	*bits = 32;
	*big_endian = 0;

	switch (header) {
	case MAGIC_68020:
		*big_endian = 1;
		*arch = "m68k";
		return true;

	case MAGIC_AMD64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_INTEL_386:
		*arch = "x86";
		return true;

	case MAGIC_SPARC64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_SPARC:
		*big_endian = 1;
		*arch = "sparc";
		return true;

	case MAGIC_MIPS_4000BE:
		*big_endian = 1;
		/* fallthrough */
	case MAGIC_MIPS_4000LE:
		*bits = 64;
		*arch = "mips";
		return true;

	case MAGIC_MIPS_3000BE:
		*big_endian = 1;
		/* fallthrough */
	case MAGIC_MIPS_3000LE:
		*arch = "mips";
		return true;

	case MAGIC_ARM64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_ARM:
		*arch = "arm";
		return true;

	case MAGIC_PPC64:
		*bits = 64;
		/* fallthrough */
	case MAGIC_PPC:
		*big_endian = 1;
		*arch = "ppc";
		return true;

	case MAGIC_RISCV64:
		*bits = 64;
		*arch = "riscv";
		return true;
	}

	return false;
}
