/* radare - LGPL - Copyright 2009-2024 - pancake, nibble */

#include <r_bin.h>
#include <r_magic.h>

static char *get_filetype(RBuffer *b) {
	ut8 buf[1024] = {0};
	char *res = NULL;
	RMagic *ck = r_magic_new (0);
	if (ck) {
		const char *tmp = NULL;
		// TODO: dir.magic is not honored here
		r_magic_load (ck, R2_SDB_MAGIC);
		r_buf_read_at (b, 0, buf, sizeof (buf));
		tmp = r_magic_buffer (ck, buf, sizeof (buf));
		if (tmp) {
			res = strdup (tmp);
		}
		r_magic_free (ck);
	}
	return res;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret != NULL) {
		ret->file = bf->file? strdup (bf->file): NULL;
		ret->type = get_filetype (bf->buf);
		ret->has_retguard = -1;
	}
	return ret;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return true;
}

static void fini(RBinFile *bf) {
	r_buf_free (bf->bo->bin_obj);
}

RBinPlugin r_bin_plugin_any = {
	.meta = {
		.name = "any",
		.desc = "Dummy format r_bin plugin",
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
