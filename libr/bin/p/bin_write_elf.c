/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBinFile *arch, const char *name, ut64 size) {
	return Elf_(r_bin_elf_resize_section) (arch->o->bin_obj, name, size);
}

static bool scn_perms(RBinFile *arch, const char *name, int perms) {
	return Elf_(r_bin_elf_section_perms) (arch->o->bin_obj, name, perms);
}

static int rpath_del(RBinFile *arch) {
	return Elf_(r_bin_elf_del_rpath) (arch->o->bin_obj);
}

#if !R_BIN_ELF64
RBinWrite r_bin_write_elf = {
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
};
#endif
