/* radare - LGPL - Copyright 2009-2016 - pancake, nibble */

#include <r_types.h>
#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBinFile *arch, const char *name, ut64 size) {
	struct Elf_(r_bin_elf_obj_t) *obj = arch->o->bin_obj;
	int ret = Elf_(r_bin_elf_resize_section) (arch->o->bin_obj, name, size);
	r_buf_free (arch->buf);
	arch->buf = obj->b;
	obj->b = NULL;
	return ret;
}

static bool scn_perms(RBinFile *arch, const char *name, int perms) {
	struct Elf_(r_bin_elf_obj_t) *obj = arch->o->bin_obj;
	int ret = Elf_(r_bin_elf_section_perms) (arch->o->bin_obj, name, perms);
	r_buf_free (arch->buf);
	arch->buf = obj->b;
	obj->b = NULL;
	return ret;
}

static int rpath_del(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *obj = arch->o->bin_obj;
	int ret = Elf_(r_bin_elf_del_rpath) (arch->o->bin_obj);
	r_buf_free (arch->buf);
	arch->buf = obj->b;
	obj->b = NULL;
	return ret;
}

static bool chentry(RBinFile *arch, ut64 addr) {
	struct Elf_(r_bin_elf_obj_t) *obj = arch->o->bin_obj;
	int ret = Elf_(r_bin_elf_entry_write) (arch->o->bin_obj, addr);
	r_buf_free (arch->buf);
	arch->buf = obj->b;
	obj->b = NULL;
	return ret;
}

#if !R_BIN_ELF64
RBinWrite r_bin_write_elf = {
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
};
#endif
