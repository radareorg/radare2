/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#define R_BIN_ELF64 1
#include "bin_write_elf.c"

struct r_bin_write_t r_bin_write_elf64 = {
	.scn_resize = &scn_resize,
};
