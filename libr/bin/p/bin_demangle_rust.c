/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

RBinDemanglePlugin r_bin_demangle_plugin_rust = {
	.meta = {
		.name = "rust",
		.desc = "Rust demangler",
		.license = WITH_GPL ? "GPL-2.0-or-later" : "MIT",
	},
	.type = R_BIN_LANG_RUST,
	.demangle = r_bin_demangle_rust,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_DEMANGLE,
	.data = &r_bin_demangle_plugin_rust,
	.version = R2_VERSION,
};
#endif
