/* radare - LGPL - Copyright 2009-2013 - nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_magic.h>

static const char * get_filetype (RBinFile *arch) {
	const char *res = NULL;
	ut8 test_buffer[4096] = {0};
	RMagic * ck = r_magic_new (0);

	if (ck && arch && arch->buf) {
		r_magic_load (ck, R_MAGIC_PATH);
		r_buf_read_at(arch->buf, 0, test_buffer, 4096);
		res = r_magic_buffer (ck, test_buffer, 4096);
	}
	if (!res) res = "";
	return res;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;

	if(!(ret = R_NEW0 (RBinInfo)))
		return NULL;

	ret->lang = "";
	if (arch->file)
		strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	else *ret->file = 0;

	strncpy (ret->rpath, "", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, get_filetype (arch), R_BIN_SIZEOF_STRINGS);
	ret->has_pi = 0;
	ret->has_canary = 0;
	strncpy (ret->bclass, "", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "", R_BIN_SIZEOF_STRINGS);
	ret->bits = 32;
	ret->big_endian = 0;
	ret->has_va = 0;
	ret->has_nx = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static int load(RBinFile *arch) {
	return R_TRUE;
}

static int destroy(RBinFile *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
}

struct r_bin_plugin_t r_bin_plugin_any = {
	.name = "any",
	.desc = "Dummy format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = NULL,
	.load = &load,
	.load_bytes = NULL,
	.destroy = &destroy,
	.check = NULL,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = NULL,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.dbginfo = NULL,
	.create = NULL,
	.write = NULL,
	.minstrlen = 0,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_any
};
#endif
