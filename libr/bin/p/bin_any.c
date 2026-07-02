/* radare - LGPL - Copyright 2009-2025 - pancake */

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

static void fini(RBinFile *bf) {
	RBuffer *buf = (RBuffer *)bf->bo->bin_obj;
	r_unref (buf);
}

RBinPlugin r_bin_plugin_any = {
	.meta = {
		.name = "any",
		.desc = "Dummy loader based on RMagic",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.load = load,
	.destroy = fini,
	.info = info,
	.minstrlen = 0,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_any,
	.version = R2_VERSION
};
#endif
