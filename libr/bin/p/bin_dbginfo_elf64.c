/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#define R_BIN_ELF64 1
#include "bin_dbginfo_elf.c"

struct r_bin_dbginfo_t r_bin_dbginfo_elf64 = {
	.get_line = &get_line,
};
