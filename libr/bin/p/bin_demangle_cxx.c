/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

RBinDemanglePlugin r_bin_demangle_plugin_cxx = {
	.meta = {
		.name = "c++",
		.desc = "C++ demangler",
		.license = WITH_GPL ? "GPL-2.0-or-later" : "MIT",
	},
	.type = R_BIN_LANG_CXX,
	.aliases = "cxx",
	.demangle = r_bin_demangle_cxx,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_DEMANGLE,
	.data = &r_bin_demangle_plugin_cxx,
	.version = R2_VERSION,
};
#endif
