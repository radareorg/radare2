/* radare - LGPL - Copyright 2011-2017 - ninjahacker */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "zimg/zimg.h"

static Sdb *get_sdb(RBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	struct r_bin_zimg_obj_t *bin = (struct r_bin_zimg_obj_t *) bf->o->bin_obj;
	return bin? bin->kv: NULL;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 size, ut64 loadaddr, Sdb *sdb){
	void *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || size == 0 || size == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, size);
	res = r_bin_zimg_new_buf (tbuf);
	r_buf_free (tbuf);
	return res;
}

static bool load(RBinFile *arch) {
	const ut8 *bytes = arch? r_buf_buffer (arch->buf): NULL;
	ut64 size = arch? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) {
		return false;
	}
	arch->o->bin_obj = load_bytes (arch, bytes, size, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj? true: false;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 8) {
		// Checking ARM zImage kernel
		if (!memcmp (buf, "\x00\x00\xa0\xe1\x00\x00\xa0\xe1", 8)) {
			return true;
		}
	}
	// TODO: Add other architectures
	return false;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = arch->file? strdup (arch->file): NULL;
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
	.name = "zimg",
	.desc = "zimg format bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_zimg,
	.version = R2_VERSION
};
#endif
