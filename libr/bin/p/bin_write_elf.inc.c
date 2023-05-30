/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBinFile *bf, const char *name, ut64 size) {
	return Elf_(resize_section) (bf, name, size);
}

static bool scn_perms(RBinFile *bf, const char *name, int perms) {
	return Elf_(section_perms) (bf, name, perms);
}

static int rpath_del(RBinFile *bf) {
	return Elf_(del_rpath) (bf);
}

static bool chentry(RBinFile *bf, ut64 addr) {
	return Elf_(entry_write) (bf, addr);
}
