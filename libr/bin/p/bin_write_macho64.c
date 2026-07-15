/* radare - LGPL - Copyright 2016 pancake */

#define R_BIN_MACHO64 1
#include "bin_write_macho.c"

RBinWrite r_bin_write_macho64 = {
#if 0
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
#endif
	.seg_perms = &seg_perms,
	.addlib = &addlib,
};
