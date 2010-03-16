/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBin *bin, const char *name, ut64 size) {
	return Elf_(r_bin_elf_resize_section) (bin->bin_obj, name, size);
}

static int rpath_del(RBin *bin) {
	return Elf_(r_bin_elf_del_rpath) (bin->bin_obj);
}

#if !R_BIN_ELF64
struct r_bin_write_t r_bin_write_elf = {
	.scn_resize = &scn_resize,
	.rpath_del = &rpath_del,
};
#endif

