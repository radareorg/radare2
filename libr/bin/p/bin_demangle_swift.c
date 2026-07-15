/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

static char *demangle(RBinFile *bf, const char *symbol, ut64 vaddr) {
	(void)vaddr;
	RBin *bin = bf? bf->rbin: NULL;
	bool usecmd = bin? bin->options.demangle_usecmd: false;
	bool trylib = bin? bin->options.demangle_trylib: true;
	return r_bin_demangle_swift (symbol, usecmd, trylib);
}

RBinDemanglePlugin r_bin_demangle_plugin_swift = {
	.meta = {
		.name = "swift",
		.desc = "Swift demangler",
		.license = "LGPL-3.0-only",
	},
	.type = R_BIN_LANG_SWIFT,
	.demangle = demangle,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_DEMANGLE,
	.data = &r_bin_demangle_plugin_swift,
	.version = R2_VERSION,
};
#endif
