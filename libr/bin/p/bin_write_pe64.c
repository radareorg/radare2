/* radare - LGPL - Copyright 2009-2017 pancake */

#define R_BIN_PE64 1
#include "bin_write_pe.c"

RBinWrite r_bin_write_pe64 = {
	.scn_perms = &scn_perms
};
