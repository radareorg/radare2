/* radare - MIT - 2024 - pancake */

#include <r_bin.h>

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 0x10) {
		ut8 buf[5] ={0};
		r_buf_read_at (b, 0, buf, sizeof (buf));
		return !memcmp (buf, "UF2\n", 4);
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("io"); // requires IO redirection to work
	ret->machine = strdup ("Microsoft UF2"); // XXX
	ret->bclass = strdup ("uf2://");
	ret->os = strdup ("hw"); // aka baremetal
	ret->arch = strdup ("arm");
	ret->bits = 32;
	ret->has_va = 1;
	ret->big_endian = 1;
	return ret;
}

RBinPlugin r_bin_plugin_uf2 = {
	.meta = {
		.name = "uf2",
		.author = "pancake",
		.desc = "Microsoft Unified Firmware v2",
		.license = "MIT",
	},
	.load = &load,
	.check = &check,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_uf2,
	.version = R2_VERSION
};
#endif
