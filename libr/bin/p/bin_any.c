/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_magic.h>

static char *get_filetype(RBuffer *b) {
	ut8 buf[4096] = { 0 };
	char *res = NULL;
	RMagic *ck = r_magic_new (0);
	if (!ck) {
		return NULL;
	}
	const char *tmp = NULL;
	// TODO: dir.magic not honored here
	r_magic_load (ck, R2_SDB_MAGIC);
	r_buf_read_at (b, 0, buf, sizeof (buf));
	tmp = r_magic_buffer (ck, buf, sizeof (buf));
	if (tmp) {
		res = strdup (tmp);
	}
	r_magic_free (ck);
	return res;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = "";
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = get_filetype (bf->buf);
	ret->has_pi = 0;
	ret->has_canary = 0;
	ret->has_retguard = -1;
	ret->big_endian = 0;
	ret->has_va = 0;
	ret->has_nx = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static void destroy(RBinFile *bf) {
	r_buf_free (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

RBinPlugin r_bin_plugin_any = {
	.name = "any",
	.desc = "Dummy format r_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.baddr = &baddr,
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
