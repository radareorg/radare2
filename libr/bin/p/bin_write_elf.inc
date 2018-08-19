/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#include <r_types.h>
#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBinFile *bf, const char *name, ut64 size) {
	struct Elf_(r_bin_elf_obj_t) *obj = bf->o->bin_obj;
	int ret = Elf_(r_bin_elf_resize_section) (bf->o->bin_obj, name, size);
	r_buf_free (bf->buf);
	bf->buf = obj->b;
	obj->b = NULL;
	return ret;
}

static bool scn_perms(RBinFile *bf, const char *name, int perms) {
	struct Elf_(r_bin_elf_obj_t) *obj = bf->o->bin_obj;
	int ret = Elf_(r_bin_elf_section_perms) (bf->o->bin_obj, name, perms);
	r_buf_free (bf->buf);
	bf->buf = obj->b;
	obj->b = NULL;
	return ret;
}

static int rpath_del(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t) *obj = bf->o->bin_obj;
	int ret = Elf_(r_bin_elf_del_rpath) (bf->o->bin_obj);
	r_buf_free (bf->buf);
	bf->buf = obj->b;
	obj->b = NULL;
	return ret;
}

static bool chentry(RBinFile *bf, ut64 addr) {
	struct Elf_(r_bin_elf_obj_t) *obj = bf->o->bin_obj;
	int ret = Elf_(r_bin_elf_entry_write) (bf->o->bin_obj, addr);
	r_buf_free (bf->buf);
	bf->buf = obj->b;
	obj->b = NULL;
	return ret;
}
