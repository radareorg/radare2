/* radare - LGPL - Copyright 2009-2026 - pancake */

#include <r_bin.h>

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->has_retguard = -1;
	return ret;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return true;
}

RBinPlugin r_bin_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "Dummy bin loader",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.load = load,
	.info = info,
	.minstrlen = 0,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_null,
	.version = R2_VERSION
};
#endif
