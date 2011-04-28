/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#define R_BIN_MACH064 1
#include "bin_mach0.c"

static int check(RBinArch *arch) {
	if (!memcmp (arch->buf->buf, "\xfe\xed\xfa\xcf", 4) ||
		!memcmp (arch->buf->buf, "\xcf\xfa\xed\xfe", 4))
		return R_TRUE;
	return R_FALSE;
}

struct r_bin_plugin_t r_bin_plugin_mach064 = {
	.name = "mach064",
	.desc = "mach064 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = NULL,
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
	.data = &r_bin_plugin_mach064
};
#endif
