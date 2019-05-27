/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_types.h>
#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBinFile *bf, const char *name, ut64 size) {
	return Elf_(r_bin_elf_resize_section) (bf, name, size);
}

static bool scn_perms(RBinFile *bf, const char *name, int perms) {
	return Elf_(r_bin_elf_section_perms) (bf->o->bin_obj, name, perms);
}

static int rpath_del(RBinFile *bf) {
	return Elf_(r_bin_elf_del_rpath) (bf->o->bin_obj);
}

static bool chentry(RBinFile *bf, ut64 addr) {
	return Elf_(r_bin_elf_entry_write) (bf->o->bin_obj, addr);
}
