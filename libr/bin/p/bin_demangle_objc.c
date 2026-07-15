/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

static char *demangle(RBinFile *bf, const char *symbol, ut64 vaddr) {
	(void)bf;
	(void)vaddr;
	return r_bin_demangle_objc (NULL, symbol);
}

RBinDemanglePlugin r_bin_demangle_plugin_objc = {
	.meta = {
		.name = "objc",
		.desc = "Objective-C demangler",
		.license = "LGPL-3.0-only",
	},
	.type = R_BIN_LANG_OBJC,
	.demangle = demangle,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_DEMANGLE,
	.data = &r_bin_demangle_plugin_objc,
	.version = R2_VERSION,
};
#endif
