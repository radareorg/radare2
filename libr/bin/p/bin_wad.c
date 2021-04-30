/* radare - LGPL3 - 2021 - murphy */

#include <r_bin.h>
#include <r_lib.h>
#include "wad/wad.h"

static struct wad_hdr loaded_header;

static bool check_buffer(RBuffer *b) {
	r_return_val_if_fail (b, false);
	ut32 sig[4];
	if (r_buf_read_at (b, 0, sig, 4) != 4) {
		return false;
	}
	if (memcmp (sig, "IWAD", 4) && memcmp (sig, "PWAD", 4)) {
        eprintf ("Not a valid WAD file");
		return false;
	}
    return true;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	if (!check_buffer (buf)) {
		return false;
	}
    if (r_buf_read_at (b, 0, (ut8*)&loaded_header, sizeof (loaded_header)) == WAD_HDR_SIZE) {
		*bin_obj = &loaded_header;
		return true;
	}
    eprintf ("Truncated Header\n");
	return false;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);*
	ret->type = strdup ("WAD");
	ret->machine = strdup ("DOOM WAD");
	ret->os = strdup ("DOOM Engine");
	ret->arch = strdup ("any");
	ret->bits = 32;
    ret->entries = loaded_header.numlumps;
    ret->big_endian = 0;
	ret->dbg_info = 0;
    ret->has_va = 0;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_nes = {
	.name = "wad",
	.desc = "DOOM WAD format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = NULL,
	.baddr = NULL,
    .entries = NULL,
	.check_buffer = &check_buffer,
	.load_buffer = &load_buffer,
	.baddr = &baddr,
    .sections = NULL,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nes,
	.version = R2_VERSION
};
#endif
