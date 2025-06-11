/* radare - LGPL - Copyright 2011-2025 - ninjahacker */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "zimg/zimg.h"

static Sdb *get_sdb(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	struct r_bin_zimg_obj_t *bin = (struct r_bin_zimg_obj_t *) bf->bo->bin_obj;
	return bin? bin->kv: NULL;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	bf->bo->bin_obj = r_bin_zimg_new_buf (b);
	return bf->bo->bin_obj != NULL;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 zimghdr[8];
	if (r_buf_read_at (b, 0, zimghdr, sizeof (zimghdr))) {
		// Checking ARM zImage kernel
		if (!memcmp (zimghdr, "\x00\x00\xa0\xe1\x00\x00\xa0\xe1", 8)) {
			return true;
		}
	}
	return false;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("Linux zImage Kernel");
	ret->has_va = false;
	ret->bclass = strdup ("Compressed Linux Kernel");
	ret->rclass = strdup ("zimg");
	ret->os = strdup ("linux");
	ret->subsystem = strdup ("linux");
	ret->machine = strdup ("ARM"); // TODO: can be other cpus
	ret->arch = strdup ("arm");
	ret->lang = "C";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; // 1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

RBinPlugin r_bin_plugin_zimg = {
	.meta = {
		.name = "zimg",
		.author = "ninjahacker",
		.desc = "Compressed Linux Kernel Image",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_zimg,
	.version = R2_VERSION
};
#endif
