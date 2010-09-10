/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#define R_BIN_PE64 1
#include "bin_pe.c"

static int check(RBin *bin) {
	ut8 *buf;
	int n, idx, ret = R_FALSE;

	if ((buf = (ut8*)r_file_slurp_range (bin->file, 0, 0xffff+0x20, &n))) {
		idx = buf[0x3c]|(buf[0x3d]<<8);
		if (n>=idx+0x20)
		if (!memcmp (buf, "\x4d\x5a", 2) &&
			!memcmp (buf+idx, "\x50\x45", 2) && 
			!memcmp (buf+idx+0x18, "\x0b\x02", 2))
			ret = R_TRUE;
		free (buf);
	}
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.extract = NULL,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.main = &binmain,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64
};
#endif
