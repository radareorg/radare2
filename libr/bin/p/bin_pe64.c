/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#define R_BIN_PE64 1
#include "bin_pe.c"

struct r_bin_handle_t r_bin_plugin_pe64 = {
	.name = "bin_pe64",
	.desc = "pe64 (pe32+) bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.baddr = &baddr,
	.entry = &entry,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.resize_section = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64
};
#endif
