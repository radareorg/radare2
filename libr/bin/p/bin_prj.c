/* radare - MIT - Copyright 2026 - pancake */

#include <r_bin.h>

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 header[8];
	return r_buf_read_at (b, 0, header, sizeof (header)) == sizeof (header)
		&& !memcmp (header, "RPRJ", 4);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("radare2 project");
	ret->bclass = strdup ("RPRJ");
	ret->rclass = strdup ("prj");
	ret->has_retguard = -1;
	return ret;
}

static RVecRBinString *strings(RBinFile *bf) {
	return NULL;
}

RBinPlugin r_bin_plugin_prj = {
	.meta = {
		.name = "prj",
		.desc = "Radare2 binary project",
		.author = "pancake",
		.license = "MIT",
	},
	.check = check,
	.load = load,
	.info = info,
	.strings = strings,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_prj,
	.version = R2_VERSION
};
#endif
