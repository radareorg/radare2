/* radare - LGPL - Copyright 2011-2015 - ninjahacker */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "zimg/zimg.h"

#define DEBUG_PRINTF 0

#if DEBUG_PRINTF
#define dprintf eprintf
#else
#define dprintf if (0)eprintf
#endif

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	struct r_bin_zimg_obj_t *bin = (struct r_bin_zimg_obj_t *) o->bin_obj;
	if (bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 size, ut64 loadaddr, Sdb *sdb){
	void *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || size == 0 || size == UT64_MAX) return NULL;
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, size);
	res = r_bin_zimg_new_buf (tbuf);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 size = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) return false;
	arch->o->bin_obj = load_bytes (arch, bytes, size, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? true: false;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
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
	if (!ret) return NULL;
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
	ret->dbg_info = 0; //1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_zimg = {
	.name = "zimg",
	.desc = "zimg format bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_zimg,
	.version = R2_VERSION
};
#endif
