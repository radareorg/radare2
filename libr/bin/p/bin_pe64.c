/* radare - LGPL - Copyright 2009-2013 - nibble */

#define R_BIN_PE64 1
#include "bin_pe.c"

static int check(RBinFile *arch) {
	int idx, ret = R_FALSE;
	if (!arch || !arch->buf || !arch->buf->buf)
		return R_FALSE;
	idx = arch->buf->buf[0x3c]|(arch->buf->buf[0x3d]<<8);
	if (arch->buf->length>=idx+0x20)
		if (!memcmp (arch->buf->buf, "\x4d\x5a", 2) &&
			!memcmp (arch->buf->buf+idx, "\x50\x45", 2) && 
			!memcmp (arch->buf->buf+idx+0x18, "\x0b\x02", 2))
			ret = R_TRUE;
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.relocs = &relocs,
	.meta = NULL,
	.write = NULL,
	.get_vaddr = &get_vaddr,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64
};
#endif
