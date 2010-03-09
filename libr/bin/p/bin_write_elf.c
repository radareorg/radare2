/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>

static int scn_set(RBin *bin, RBinSection *scn) {
	/* TODO */
	return R_FALSE;
}

#if !R_BIN_ELF64
struct r_bin_write_t r_bin_write_elf = {
	.scn_set = &scn_set,
};
#endif

