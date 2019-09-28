/* radare - LGPL - Copyright 2018 pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static bool load(RBin *bin) {
	if (!bin || !bin->cur) {
	    return false;
	}
	if (!bin->file) {
	   	bin->file = bin->cur->file;
	}
	return bin->cur->xtr_obj? true : false;
}


RBinLdrPlugin r_bin_ldr_plugin_ldr_linux = {
	.name = "ldr.linux",
	.desc = "Linux loader plugin for RBin",
	.license = "MIT",
	.load = &load,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_LDR,
	.data = &r_bin_ldr_plugin_ldr_linux,
	.version = R2_VERSION
};
#endif
