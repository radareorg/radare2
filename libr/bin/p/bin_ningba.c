/* radare - LGPL - 2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/gba.h"

static int check(RBinFile *arch) {
	ut8 lict[156];
	if (!arch || !arch->buf)
		return 0;
	r_buf_read_at (arch->buf, 0x4, lict, 156);
	return (!memcmp (lict, lic_gba, 156))? 1: 0;
}

static int load(RBinFile *arch) {
	if (check (arch)) return R_TRUE;
	return R_FALSE;
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
}

static RList* entries(RBinFile *arch) {
	RList *ret = r_list_new ();
	RBinAddr *ptr = NULL;

	if (arch && arch->buf) {
		if (!ret)
			return NULL;
		ret->free = free;
		if (!(ptr = R_NEW0 (RBinAddr)))
			return ret;
		ptr->offset = ptr->rva = 0x0;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	ut8 rom_info[16];
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}

	ret->lang = NULL;
	r_buf_read_at (arch->buf, 0xa0, rom_info, 16);
	strncpy (ret->file, rom_info, 12);
	strncpy (ret->type, &rom_info[12], 4);
	strncpy (ret->machine, "Gameboy Advanced", sizeof (ret->machine)-1);
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strcpy (ret->arch, "arm");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Gameboy Advanced format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = &entries,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningba
};
#endif
