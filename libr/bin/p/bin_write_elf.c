/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include "bin_write_elf.inc"

RBinWrite r_bin_write_elf = {
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
};
