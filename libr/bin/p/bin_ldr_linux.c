/* radare - LGPL - Copyright 2018-2024 pancake */

#include <r_bin.h>

static bool load(RBin *bin) {
	if (!bin || !bin->cur) {
		return false;
	}
	if (!bin->file) {
	   	bin->file = bin->cur->file;
	}
	return bin->cur->xtr_obj != NULL;
}


RBinLdrPlugin r_bin_ldr_plugin_ldr_linux = {
	.meta = {
		.name = "ldr.linux",
		.author = "pancake",
		.desc = "Linux Kernel loader",
		.license = "MIT",
	},
	.load = &load,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_LDR,
	.data = &r_bin_ldr_plugin_ldr_linux,
	.version = R2_VERSION
};
#endif
