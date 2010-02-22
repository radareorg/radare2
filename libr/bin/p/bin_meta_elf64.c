/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#define R_BIN_ELF64 1
#include "bin_meta_elf.c"

struct r_bin_meta_t r_bin_meta_elf64 = {
	.get_line = &get_line,
};
